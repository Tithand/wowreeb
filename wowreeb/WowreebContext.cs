/*
    MIT License

    Copyright (c) 2017 namreeb http://github.com/namreeb legal@namreeb.org

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

*/

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Windows.Forms;
using System.Xml.Linq;
using wowreeb.Properties;

namespace wowreeb
{
    class WowreebContext : ApplicationContext
    {
        #region Injection
        [DllImport("wowreeb.dll", CharSet = CharSet.Unicode, EntryPoint = "Inject")]
        private static extern uint Inject32([MarshalAs(UnmanagedType.LPWStr)] string exe,
            [MarshalAs(UnmanagedType.LPWStr)] string dll, [MarshalAs(UnmanagedType.LPStr)] string authServer, float fov,
            [MarshalAs(UnmanagedType.LPWStr)] string clrDll, [MarshalAs(UnmanagedType.LPWStr)] string clrTypeName,
            [MarshalAs(UnmanagedType.LPWStr)] string clrMethodName);

        [DllImport("wowreeb64.dll", CharSet = CharSet.Unicode, EntryPoint = "Inject")]
        private static extern uint Inject64([MarshalAs(UnmanagedType.LPWStr)] string exe,
            [MarshalAs(UnmanagedType.LPWStr)] string dll, [MarshalAs(UnmanagedType.LPStr)] string authServer, float fov,
            [MarshalAs(UnmanagedType.LPWStr)] string clrDll, [MarshalAs(UnmanagedType.LPWStr)] string clrTypeName,
            [MarshalAs(UnmanagedType.LPWStr)] string clrMethodName);

        private static uint Inject(string exe, string dll, string authServer, float fov, string clrDll,
            string clrTypeName, string clrMethodName)
        {
            return Environment.Is64BitProcess
                ? Inject64(exe, dll, authServer, fov, clrDll, clrTypeName, clrMethodName)
                : Inject32(exe, dll, authServer, fov, clrDll, clrTypeName, clrMethodName);
        }
        #endregion

        #region Binary type detection
        [SuppressMessage("ReSharper", "InconsistentNaming")]
        private enum BinaryType : uint
        {
            SCS_32BIT_BINARY = 0,
            SCS_64BIT_BINARY = 6,
            SCS_DOS_BINARY = 1,
            SCS_OS216_BINARY = 5,
            SCS_PIF_BINARY = 3,
            SCS_POSIX_BINARY = 4,
            SCS_WOW_BINARY = 2
        }

        // taken from https://stackoverflow.com/questions/44337501/get-type-of-binary-on-filesystem-via-c-sharp-running-in-64-bit
        private static BinaryType? GetBinaryType(string path)
        {
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                stream.Seek(0x3C, SeekOrigin.Begin);
                using (var reader = new BinaryReader(stream))
                {
                    if (stream.Position + sizeof(int) > stream.Length)
                        return null;
                    var peOffset = reader.ReadInt32();
                    stream.Seek(peOffset, SeekOrigin.Begin);
                    if (stream.Position + sizeof(uint) > stream.Length)
                        return null;
                    var peHead = reader.ReadUInt32();
                    if (peHead != 0x00004550) // "PE\0\0"
                        return null;
                    if (stream.Position + sizeof(ushort) > stream.Length)
                        return null;
                    switch (reader.ReadUInt16())
                    {
                        case 0x14c:
                            return BinaryType.SCS_32BIT_BINARY;
                        case 0x8664:
                            return BinaryType.SCS_64BIT_BINARY;
                        default:
                            return null;
                    }
                }
            }
        }
        #endregion

        private struct VersionEntry
        {
            public string Path;
            public string AuthServer;
            public string SHA256;
            public float Fov;
            public string CLRDll;
            public string CLRTypeName;
            public string CLRMethodName;
        }

        private readonly Dictionary<string, VersionEntry> _versionEntries = new Dictionary<string, VersionEntry>();
        private readonly NotifyIcon _trayIcon;

        public WowreebContext()
        {
            if (!ParseConfig("config.xml"))
            {
                MessageBox.Show(@"config.xml load failed");
                Application.Exit();
            }

            var menuItems = new List<MenuItem>(_versionEntries.Count);
            menuItems.AddRange(_versionEntries.Select(entry => new MenuItem(entry.Key, (sender, args) => Click(entry.Key))));
            menuItems.Add(new MenuItem("-"));
            menuItems.Add(new MenuItem("Exit", Exit));

            _trayIcon = new NotifyIcon
            {
                Icon = Resources.WoW,
                ContextMenu = new ContextMenu(menuItems.ToArray()),
                Visible = true,
                Text = @"Wowreeb Launcher"
            };
        }

        private static bool CheckExecutableIntegrity(string path, string expected)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(path))
                {
                    var checksum = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", string.Empty).ToLower();

                    return checksum == expected.ToLower();
                }
            }
        }

        private void Click(string entry)
        {
            if (!_versionEntries.ContainsKey(entry))
                throw new Exception("Could not find entry " + entry);

            var sha256 = _versionEntries[entry].SHA256;
            var path = _versionEntries[entry].Path;

            if (sha256 != string.Empty && !CheckExecutableIntegrity(path, sha256))
            {
                MessageBox.Show($"File {path} failed security check!", @"SHA256 Failure!", MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            var binType = GetBinaryType(path);

            if (binType == BinaryType.SCS_64BIT_BINARY)
            {
                Inject(path, Directory.GetCurrentDirectory() + "\\wowreeb64.dll", _versionEntries[entry].AuthServer,
                    _versionEntries[entry].Fov, _versionEntries[entry].CLRDll, _versionEntries[entry].CLRTypeName,
                    _versionEntries[entry].CLRMethodName);
            }
            // target executable is 32 bit
            else if (binType == BinaryType.SCS_32BIT_BINARY)
            {
                Inject(path, Directory.GetCurrentDirectory() + "\\wowreeb.dll", _versionEntries[entry].AuthServer,
                    _versionEntries[entry].Fov, _versionEntries[entry].CLRDll, _versionEntries[entry].CLRTypeName,
                    _versionEntries[entry].CLRMethodName);
            }
            else
                MessageBox.Show($"Unknown binary type {binType} for {path}");
        }

        private void Exit(object sender, EventArgs e)
        {
            _trayIcon.Visible = false;
            Application.Exit();
        }

        private bool ParseConfig(string filename)
        {
            var doc = XElement.Load(filename);

            foreach (var c in doc.Descendants())
            {
                switch (c.Name.ToString().ToLower())
                {
                    case "realm":
                    {
                        var name = string.Empty;
                        var ins = new VersionEntry {AuthServer = string.Empty, SHA256 = string.Empty};

                        foreach (var a in c.Attributes())
                        {
                            switch (a.Name.ToString().ToLower())
                            {
                                case "name":
                                    name = a.Value;
                                    break;

                                default:
                                    return false;
                            }
                        }

                        foreach (var e in c.Elements())
                        {
                            switch (e.Name.ToString().ToLower())
                            {
                                case "exe":
                                    foreach (var attr in e.Attributes())
                                    {
                                        switch (attr.Name.ToString().ToLower())
                                        {
                                            case "path":
                                                ins.Path = attr.Value;
                                                break;
                                            case "sha256":
                                                ins.SHA256 = attr.Value;
                                                break;
                                            default:
                                                return false;
                                        }
                                    }
                                    break;

                                case "authserver":
                                    foreach (var attr in e.Attributes())
                                    {
                                        switch (attr.Name.ToString().ToLower())
                                        {
                                            case "host":
                                                ins.AuthServer = attr.Value;
                                                break;
                                            default:
                                                return false;
                                        }
                                    }
                                    break;

                                case "fov":
                                    foreach (var attr in e.Attributes())
                                    {
                                        switch (attr.Name.ToString().ToLower())
                                        {
                                            case "value":
                                                if (!float.TryParse(e.FirstAttribute.Value, out ins.Fov))
                                                    throw new FormatException("Unable to parse FoV");
                                                break;
                                            default:
                                                return false;
                                        }
                                    }
                                    break;

                                case "clr":
                                    foreach (var attr in e.Attributes())
                                    {
                                        switch (attr.Name.ToString().ToLower())
                                        {
                                            case "path":
                                                ins.CLRDll = attr.Value;
                                                break;
                                            case "type":
                                                ins.CLRTypeName = attr.Value;
                                                break;
                                            case "method":
                                                ins.CLRMethodName = attr.Value;
                                                break;
                                            default:
                                                return false;
                                        }
                                    }
                                    break;
                                default:
                                    return false;
                            }
                        }

                        if (name == string.Empty)
                            return false;

                        _versionEntries[name] = ins;

                        break;
                    }
                }
            }
            return true;
        }
    }
}
