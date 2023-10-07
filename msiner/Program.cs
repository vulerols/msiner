using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.IO;
using System.Text.RegularExpressions;
using WixToolset.Dtf.WindowsInstaller;
class Msiner
{
    static void Copyright()
    {
        Console.WriteLine("███╗   ███╗███████╗██╗███╗   ██╗███████╗██████╗");
        Console.WriteLine("████╗ ████║██╔════╝██║████╗  ██║██╔════╝██╔══██╗");
        Console.WriteLine("██╔████╔██║███████╗██║██╔██╗ ██║█████╗  ██████╔╝");
        Console.WriteLine("██║╚██╔╝██║╚════██║██║██║╚██╗██║██╔══╝  ██╔══██╗");
        Console.WriteLine("██║ ╚═╝ ██║███████║██║██║ ╚████║███████╗██║  ██║");
        Console.WriteLine("╚═╝     ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝");
        Console.WriteLine("Description: Security tool to check MSI installer file on LPE recovery mode CVE-2023-26078 and CVE-2023-26078");
        Console.WriteLine("Author: Nikita Kurganov aka vulerols");
        Console.WriteLine("");
    }

    static void Man()
    {
        Console.WriteLine("Usage: msiner.exe <file.msi>");
    }

    static List<string> DumpReinstallExecuteActions(string msiFilePath)
    {
        List<string> reinstall_actions = new List<string> { };
        try
        {
            using (Database db = new Database(msiFilePath, DatabaseOpenMode.ReadOnly))
            {
                using (View view = db.OpenView($"SELECT * FROM InstallExecuteSequence"))
                {
                    view.Execute(null);
                    while (true)
                    {
                        using (Record record = view.Fetch())
                        {
                            if (record == null)
                                break;

                            string value_action = record[1]?.ToString() ?? "null";
                            string value_action_condition = record[2]?.ToString() ?? "null";
                            string lower_value_action_condition = value_action_condition.ToLower();

                            if (lower_value_action_condition == "")
                            {
                                reinstall_actions.Add(value_action.ToLower());
                                continue;
                            }

                            if (lower_value_action_condition == "installed")
                            {
                                reinstall_actions.Add(value_action.ToLower());
                                continue;
                            }

                            if (!lower_value_action_condition.Contains("not installed") && lower_value_action_condition.Contains("installed") && !lower_value_action_condition.Contains("not reinstall"))
                            {
                                reinstall_actions.Add(value_action.ToLower());
                                continue;
                            }

                        }
                    }
                    return reinstall_actions;

                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading tables: {ex.Message}");
            return reinstall_actions;
        }
    }

    static List<string> DumpDirectory(string msiFilePath)
    {
        List<string> msi_directory = new List<string> { };
        try
        {
            using (Database db = new Database(msiFilePath, DatabaseOpenMode.ReadOnly))
            {
                using (View view = db.OpenView($"SELECT * FROM Directory"))
                {
                    view.Execute(null);
                    while (true)
                    {
                        using (Record record = view.Fetch())
                        {
                            if (record == null)
                                break;

                            string directory = record[1]?.ToString() ?? "null";
                            string source_path = record[3]?.ToString() ?? "null";
                            string total_path = directory + " -> " + source_path;
                            msi_directory.Add(total_path);
                        }
                    }
                    return msi_directory;

                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading tables: {ex.Message}");
            return msi_directory;
        }
    }

    static bool DetectSuspitiosCmds(string msiFilePath, List<string> reinstall_actions)
    {
        string[] blacklist_msi_cmd_list = new string[] { 
            "reg", 
            "regasm", 
            "reg.exe", 
            "regasm.exe", 
            "cmd.exe", 
            "cmd", "taskkill", 
            "taskkill.exe", 
            "schtasks", 
            "schtasks.exe", 
            "powershell", 
            "powershell.exe", 
            "net.exe", 
            "net", 
            "netsh", 
            "netsh.exe", 
            "python", 
            "python.exe", 
            "sc", 
            "sc.exe", 
            "runas", 
            "runas.exe" 
        };
        
        bool flag_detect_msi = false;
        List<string> all_reinstall_commands = new List<string> { };

        try
        {
            using (Database db = new Database(msiFilePath, DatabaseOpenMode.ReadOnly))
            {
                using (View view = db.OpenView($"SELECT * FROM CustomAction"))
                {
                    view.Execute(null);
                    Console.WriteLine($"");
                    Console.WriteLine($"[*] Suspition commands:");
                    while (true)
                    {
                        using (Record record = view.Fetch())
                        {
                            if (record == null)
                                break;

                            string action_value = record[1]?.ToString() ?? "null";
                            string value = record[4]?.ToString() ?? "null";

                            Regex regex = new Regex(@"^[^\s]+");
                            Match match = regex.Match(value);

                            if (reinstall_actions.Contains(action_value.ToLower()))
                            {
                                all_reinstall_commands.Add(value);
                            }

                            if ((match.Success) && reinstall_actions.Contains(action_value.ToLower()))
                            {
                                string value_lover = match.Value;
                                value_lover = value_lover.ToLower();
                                value_lover = value_lover.Replace("\"", "");


                                if (value_lover.IndexOf("\\") >= 0)
                                {
                                    string pattern = @"[^\\]*\.exe\b";
                                    MatchCollection match_exe = Regex.Matches(value_lover, pattern);

                                    foreach (Match exe_file in match_exe)
                                    {
                                        foreach (string blacklist_cmd in blacklist_msi_cmd_list)
                                        {
                                            if (blacklist_cmd == exe_file.Value)
                                            {
                                                Console.WriteLine($"[!] {value}");
                                                flag_detect_msi = true;
                                            }
                                        }
                                    }

                                }
                                else
                                {
                                    foreach (string blacklist_cmd in blacklist_msi_cmd_list)
                                    {
                                        if (blacklist_cmd == value_lover)
                                        {
                                            Console.WriteLine($"[!] {value}");
                                            flag_detect_msi = true;

                                        }
                                    }
                                }
                            }
                        }
                    }

                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading tables: {ex.Message}");
        }

        Console.WriteLine($"");
        Console.WriteLine($"[*] All reinstall commands:");

        foreach (string command in all_reinstall_commands)
        {
            Console.WriteLine($"[!] {command}");
        }
        return flag_detect_msi;
    }
    static void Main(string[] args)
    {
        // Check if any command-line arguments were provided
        if (args.Length == 0)
        {
            Copyright();
            Man();
        }
        else
        {
            try
            {
                Copyright();
                string file_object = args[0];
                Console.WriteLine($"[*] Check msi file: {file_object}");
                List<string> reinstall_actions_list = DumpReinstallExecuteActions(file_object);
                List<string> folder_msi_list = DumpDirectory(file_object);

                Console.WriteLine($"");
                Console.WriteLine($"[*] Install MSI folders:");

                foreach (string folder_msi in folder_msi_list)
                {
                    Console.WriteLine($"[!] {folder_msi}");
                }

                if (reinstall_actions_list.Count() != 0)
                {
                    bool detect_vuln_msi = DetectSuspitiosCmds(file_object, reinstall_actions_list);
                    if (detect_vuln_msi == true)
                    {
                        Console.WriteLine($"");
                        Console.WriteLine($"[*] Verdict: DETECT");
                    }
                    else
                    {
                        Console.WriteLine($"");
                        Console.WriteLine($"[*] Verdict: CLEAN");
                    }
                }
                
            }
            catch (Exception ex)
            {
                Man();
            }
        }
    }
}

