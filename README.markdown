[![Wyeomyia smithii](https://github.com/okeuday/pest/raw/master/images/320px-Wyeomyia_smithii.jpg)](https://en.wikipedia.org/wiki/Mosquito#Lifecycle)

Primitive Erlang Security Tool (PEST)
-------------------------------------

[![Build Status](https://secure.travis-ci.org/okeuday/pest.png?branch=master)](http://travis-ci.org/okeuday/pest)
[![hex.pm version](https://img.shields.io/hexpm/v/pest.svg)](https://hex.pm/packages/pest)

Do a basic scan of Erlang source code and report any function calls that may
cause Erlang source code to be insecure.

The tool is provided in the form of an escript (an Erlang script) which may
also be used as a module.  Usage of the script is provided with the `-h`
command line argument, with the output shown below:

    Usage pest.erl [OPTION] [FILES] [DIRECTORIES]
    
      -b              Only process beam files recursively
      -c              Perform internal consistency checks
      -d DEPENDENCY   Expand the checks to include a dependency
                      (provide the dependency as a file path or directory)
      -D IDENTIFIER   Expand the checks to include a dependency from an identifier
      -e              Only process source files recursively
      -h              List available command line flags
      -i              Display checks information after expanding dependencies
      -m APPLICATION  Display a list of modules in an Erlang/OTP application
      -p DIRECTORY    Append a directory on the code server's search path list
      -r              Recursively search directories
      -s SEVERITY     Set the minimum severity to use when reporting problems
                      (default is 50)
      -U COMPONENT    Update local data related to a component
                      (valid components are: crypto, pest/dependency/IDENTIFIER)
      -v              Verbose output (set the minimum severity to 0)
      -V [COMPONENT]  Print version information
                      (valid components are: pest, crypto)

Erlang/OTP version 21.0 and higher is required.
If beam files are used, they must have been compiled with the `debug_info`
option to provide the `abstract_code` used by pest.erl.  However, pest.erl
also consumes Erlang source code, including Erlang source escript files.
If beam files are available, it is best to use the beam files with pest.erl
due to how the Erlang compiler preprocessor and optimizations can influence
function calls.

Please feel free to contribute!  To add security problems to the scan
insert information into the [list of checks](https://github.com/okeuday/pest/blob/master/src/pest.erl#L153-L215).

Usage
-----

To scan any `.beam` files in a `lib` directory recursively, use:

    ./pest.erl -b /path_to_somewhere/lib

If you want to see all possible checks,
just turn on the verbose output with `-v`:

    ./pest.erl -v -b /path_to_somewhere/lib

To check version information related to Erlang/OTP crypto, use:

    ./pest.erl -V crypto

To do a slower scan that includes indirect function calls from Erlang/OTP
(as described in [Indirect Security Concerns in Erlang/OTP](#indirect-security-concerns-in-erlangotp) and [Elixir](#indirect-security-concerns-in-elixir)), use:

    ./pest.erl -v -b -d /erlang_install_prefix/lib/erlang/lib/ /path_to_somewhere/lib

Determining checks that include all indirect function calls for Erlang/OTP 21.0
can take several minutes, so it is easier to use cached results.
The checks have already been cached for Erlang/OTP 21.0 (with the command `./pest.erl -v -b -d /erlang_install_prefix/lib/erlang/lib/ -U pest/dependency/ErlangOTP/21.0`),
which can be used to obtain the same output with:

    ./pest.erl -v -b -D ErlangOTP/21.0 /path_to_somewhere/lib

If beam files created by an Elixir project need to be checked,
the following command line could be used:

    ./pest.erl -v -b -D ErlangOTP/21.0 -D Elixir/1.6.6/21.0 /path_to_somewhere/lib

Test
----

To have pest.erl check itself, use:

    ./pest.erl -v -c -D ErlangOTP/23.0.1 ./pest.erl

Indirect Security Concerns in Erlang/OTP
----------------------------------------

Usage of various Erlang/OTP dependencies can have their own security concerns
which Erlang source code may depend on indirectly.  To provide a representation
of security concerns related to Erlang/OTP dependencies, the pest.erl script
was ran on all of the beam files installed for Erlang/OTP 21.0, with the result
provided below:

    $ ./pest.erl -v -b ~/installed/lib/erlang/lib/
     90: Port Drivers may cause undefined behavior
         erl_ddll.beam:153 (erl_ddll:try_load/3)
         megaco_flex_scanner.beam:89 (erl_ddll:load_driver/2)
         dbg.beam:[440,447,478,485] (erl_ddll:load_driver/2)
         wxe_master.beam:125 (erl_ddll:load_driver/2)
     90: NIFs may cause undefined behavior
         asn1rt_nif.beam:[58,70] (erlang:load_nif/2)
         crypto.beam:[852,865] (erlang:load_nif/2)
         erl_tracer.beam:36 (erlang:load_nif/2)
         prim_buffer.beam:48 (erlang:load_nif/2)
         prim_file.beam:98 (erlang:load_nif/2)
         zlib.beam:115 (erlang:load_nif/2)
         dyntrace.beam:[84,96] (erlang:load_nif/2)
     80: OS shell usage may require input validation
         ct_webtool.beam:[172,175,189,194,198] (os:cmd/1)
         test_server_node.beam:642 (os:cmd/1)
         dialyzer_callgraph.beam:777 (os:cmd/1)
         observer_wx.beam:561 (os:cmd/1)
         cpu_sup.beam:246 (os:cmd/1)
         memsup.beam:[685,698,730,773] (os:cmd/1)
         os_sup.beam:242 (os:cmd/1)
         yecc.beam:457 (os:cmd/1)
         system_information.beam:[655,656] (os:cmd/1)
         snmp_config.beam:[1560,1567] (os:cmd/1)
     80: OS process creation may require input validation
         prim_inet.beam:87 (erlang:open_port/2)
         ram_file.beam:400 (erlang:open_port/2)
         megaco_flex_scanner.beam:114 (erlang:open_port/2)
         os_mon.beam:[89,95] (erlang:open_port/2)
     15: Keep OpenSSL updated for crypto module use (run with "-V crypto")
         ct_config.beam:637 (crypto:block_decrypt/4)
         ct_config.beam:603 (crypto:block_encrypt/4)
         ct_make.beam:285 (compile:file/2)
         ct_netconfc.beam:[1738,1811] (ssh:_/_)
         ct_netconfc.beam:[945,1756,1758,1766,1769,1792,1801] (ssh_connection:_/_)
         ct_slave.beam:280 (ssh:_/_)
         ct_slave.beam:[281,283,287] (ssh_connection:_/_)
         ct_snmp.beam:[259,291,463,479,494,510,525,540,555,571] (snmp_config:_/_)
         ct_snmp.beam:[226,229] (snmpa:_/_)
         ct_snmp.beam:[97,102,110,111,347,371,379,384,390,395] (snmpm:_/_)
         ct_ssh.beam:[444,447,719] (ssh:_/_)
         ct_ssh.beam:[474,479,487,502,505,524,532,545,553,737,742] (ssh_connection:_/_)
         ct_ssh.beam:[449,468,562,568,574,580,586,592,598,604,610,616,622,628,634,640,646,652,658,664,670,676,682,688,694,700,706,723] (ssh_sftp:_/_)
         compile.beam:1465 (crypto:block_encrypt/4)
         dialyzer_cl.beam:562 (compile:file/2)
         dialyzer_utils.beam:98 (compile:noenv_file/2)
         diameter_tcp.beam:[198,717,719,840,842,888,897] (ssl:_/_)
         eldap.beam:[513,585,625,962,1003,1008,1122,1124] (ssl:_/_)
         ftp.beam:[1607,2203,2221,2253,2272,2292,2416,2419,2424] (ssl:_/_)
         http_transport.beam:[109,179,214,235,256,289,337,356,379,412,490] (ssl:_/_)
         httpc_handler.beam:1645 (ssl:_/_)
         httpd_script_env.beam:66 (ssl:_/_)
         hdlt_client.beam:212 (ssl:_/_)
         hdlt_ctrl.beam:[201,305,424,995,1011] (ssh:_/_)
         hdlt_ctrl.beam:[298,333,339,345,356,369,418,447,453,459,474,988,1006,1015,1017,1023,1027,1029,1441,1461,1477,1488,1497] (ssh_sftp:_/_)
         hdlt_server.beam:150 (ssl:_/_)
         hdlt_slave.beam:[154,222,227] (ssh:_/_)
         hdlt_slave.beam:[166,177] (ssh_connection:_/_)
         os_mon_mib.beam:[111,113,137,140] (snmp_shadow_table:_/_)
         os_mon_mib.beam:[90,99] (snmpa:_/_)
         otp_mib.beam:[112,115,119,121] (snmp_shadow_table:_/_)
         otp_mib.beam:[76,85] (snmpa:_/_)
         OTP-PUB-KEY.beam:[1635,8020,8080,8224,8274,8730,8778,8807,8855,9029,9077,9106,9154,9183,9231,9392,9452,9527,9577,9682,9759,9842,9888,10012,10049,14645,14706,14763,14805,14862,14915,14940,14982,15068,15116,15205,15253,15386,15412,15457,15494,15625,15667] ('OTP-PUB-KEY':_/_)
         PKCS-FRAME.beam:[199,411,440,511,552,603,632,703,744,892,921,1043,1084,1143,1202,1294,1365,1411,1536,1713,1804] ('PKCS-FRAME':_/_)
         pubkey_cert.beam:572 ('OTP-PUB-KEY':_/_)
         pubkey_cert.beam:1091 (pubkey_cert:_/_)
         pubkey_cert.beam:[66,1246] (pubkey_cert_records:_/_)
         pubkey_cert.beam:[523,558,565,567,1115,1216,1221,1236,1306,1308,1310] (public_key:_/_)
         pubkey_cert_records.beam:[40,226,239,284,298] ('OTP-PUB-KEY':_/_)
         pubkey_crl.beam:585 ('OTP-PUB-KEY':_/_)
         pubkey_crl.beam:[43,71,86,318,334,420,430,482,502,643,654,680] (pubkey_cert:_/_)
         pubkey_crl.beam:[287,316,332,343,382,387,390,398,704,709] (pubkey_cert_records:_/_)
         pubkey_crl.beam:[220,234,245,484,570,572,580,667,669,671] (public_key:_/_)
         pubkey_pbe.beam:[162,184,187,190,193,196,200,206] ('PKCS-FRAME':_/_)
         pubkey_pbe.beam:[61,66,70,76] (crypto:block_decrypt/4)
         pubkey_pbe.beam:[44,49,53] (crypto:block_encrypt/4)
         pubkey_pem.beam:[79,89,146,150] (pubkey_pbe:_/_)
         pubkey_pem.beam:[145,151] (public_key:_/_)
         pubkey_ssh.beam:[389,406,433,561] (public_key:_/_)
         public_key.beam:[249,306,1435,1477] ('OTP-PUB-KEY':_/_)
         public_key.beam:[240,297] ('PKCS-FRAME':_/_)
         public_key.beam:[504,507] (crypto:compute_key/4)
         public_key.beam:1404 (crypto:ec_curve/1)
         public_key.beam:[452,460,1382] (crypto:generate_key/2)
         public_key.beam:366 (crypto:private_decrypt/4)
         public_key.beam:432 (crypto:private_encrypt/4)
         public_key.beam:1163 (crypto:public_decrypt/4)
         public_key.beam:1159 (crypto:public_encrypt/4)
         public_key.beam:[623,624,642,667,709,714,719,756,760,769,780,797,825,860,1101,1105,1116,1220,1227,1229,1231,1234,1238,1240,1247,1349,1351] (pubkey_cert:_/_)
         public_key.beam:[145,327,346,619,644,677,761,812,1388,1396,1402,1443] (pubkey_cert_records:_/_)
         public_key.beam:[678,737,876,884,1270,1284,1322,1329,1338] (pubkey_crl:_/_)
         public_key.beam:[126,134,1150,1154] (pubkey_pem:_/_)
         public_key.beam:[436,439,992,1009] (pubkey_ssh:_/_)
         public_key.beam:[618,1037,1040,1043] (public_key:_/_)
         snmp.beam:[235,238,241,244] (snmp_app:_/_)
         snmp.beam:247 (snmp_config:_/_)
         snmp.beam:[973,1002,1005] (snmp_log:_/_)
         snmp.beam:941 (snmp_misc:_/_)
         snmp.beam:[919,922] (snmp_pdus:_/_)
         snmp.beam:[930,933] (snmp_usm:_/_)
         snmp.beam:[903,908,1040,1042,1043,1044,1045,1046,1047,1048,1049,1051,1052,1053,1054,1055,1057,1058,1059,1060,1061,1062,1064,1066,1068,1071,1074,1076,1078,1080,1082,1083,1084,1087,1089,1091,1093] (snmpa:_/_)
         snmp.beam:[1028,1029,1032,1035,1038] (snmpc:_/_)
         snmp.beam:[905,910] (snmpm:_/_)
         snmp_app.beam:[39,117,141,153] (snmp_app_sup:_/_)
         snmp_app.beam:62 (snmpa_app:_/_)
         snmp_app_sup.beam:103 (snmp_misc:_/_)
         snmp_community_mib.beam:[138,147,148,149,150,151,473,480,487,494,501,577,584] (snmp_conf:_/_)
         snmp_community_mib.beam:[163,456] (snmp_framework_mib:_/_)
         snmp_community_mib.beam:[316,419,432,444,452,528,541,608,628] (snmp_generic:_/_)
         snmp_community_mib.beam:[265,301,355,359] (snmp_target_mib:_/_)
         snmp_community_mib.beam:[68,73,76,98,102,108,110,115,118,120,125,171,178,250,257,261,267,272,297,303] (snmp_verbosity:_/_)
         snmp_community_mib.beam:[445,594] (snmpa_agent:_/_)
         snmp_community_mib.beam:657 (snmpa_error:_/_)
         snmp_community_mib.beam:[71,116,117,174] (snmpa_local_db:_/_)
         snmp_community_mib.beam:[182,185,232,416] (snmpa_mib_lib:_/_)
         snmp_conf.beam:[142,150,191,199,206,218,228,232,235,240,245] (snmp_verbosity:_/_)
         snmp_config.beam:1888 (snmp_conf:_/_)
         snmp_config.beam:[1073,1117] (snmp_misc:_/_)
         snmp_config.beam:1637 (snmp_target_mib:_/_)
         snmp_config.beam:2772 (snmp_usm:_/_)
         snmp_config.beam:[1703,1706,1731,1734,1760,1763,1795,1798,1891,1894,1928,1931,1955,1958,2022,2025,2099,2102] (snmpa_conf:_/_)
         snmp_config.beam:[2168,2171,2190,2193,2212,2215,2233,2236] (snmpm_conf:_/_)
         snmp_framework_mib.beam:[125,135,144,181,196,198,203,219,221,239,241,243,250] (snmp_conf:_/_)
         snmp_framework_mib.beam:[271,382,390,394,414,418,422,425,428,431,439,445,451,460,462,466,491] (snmp_generic:_/_)
         snmp_framework_mib.beam:[472,484,494] (snmp_misc:_/_)
         snmp_framework_mib.beam:194 (snmp_target_mib:_/_)
         snmp_framework_mib.beam:[94,98,106,108,110,114,119,130,179,261,269,274,282] (snmp_verbosity:_/_)
         snmp_framework_mib.beam:[86,405] (snmpa_agent:_/_)
         snmp_framework_mib.beam:512 (snmpa_error:_/_)
         snmp_framework_mib.beam:[257,262,275,276,283,399] (snmpa_local_db:_/_)
         snmp_framework_mib.beam:[289,292,437,443,449,455] (snmpa_mib_lib:_/_)
         snmp_generic.beam:92 (snmp_generic:_/_)
         snmp_generic.beam:[61,65,70,105,117,123,128,196,202,508,602,818,825] (snmp_generic_mnesia:_/_)
         snmp_generic.beam:[100,107,213,216,234,237,242,246,249,253,425,445,734,736] (snmp_verbosity:_/_)
         snmp_generic.beam:918 (snmpa_error:_/_)
         snmp_generic.beam:[63,67,72,80,82,112,120,125,130,133,199,205,416,439,514,798,820,827] (snmpa_local_db:_/_)
         snmp_generic.beam:[742,749,757,764] (snmpa_symbolic_store:_/_)
         snmp_generic_mnesia.beam:[91,92,104,105,109,123,145,205,216,217,226,229,231,244,270,317,318,319,321,323,352,374,383] (snmp_generic:_/_)
         snmp_generic_mnesia.beam:402 (snmpa_error:_/_)
         snmp_index.beam:[55,60,65,71,78,87,100,111] (snmp_verbosity:_/_)
         snmp_log.beam:884 (snmp_conf:_/_)
         snmp_log.beam:[649,659,668,678] (snmp_mini_mib:_/_)
         snmp_log.beam:[956,974,976] (snmp_misc:_/_)
         snmp_log.beam:[739,751,759,771,959] (snmp_pdus:_/_)
         snmp_log.beam:[123,157,175,225,237,249,256,264,324,329,334,342,362,370,433,465,507,546,548,571,574,581,584,589,593,598,602,1013,1042,1051] (snmp_verbosity:_/_)
         snmp_mini_mib.beam:[60,62] (snmp_misc:_/_)
         snmp_misc.beam:461 (snmp_mini_mib:_/_)
         snmp_misc.beam:[350,465] (snmp_misc:_/_)
         snmp_misc.beam:470 (snmp_pdus:_/_)
         snmp_note_store.beam:[148,357,377,444,447,450] (snmp_misc:_/_)
         snmp_note_store.beam:[317,323,327,334,340,345] (snmp_note_store:_/_)
         snmp_note_store.beam:[120,127,143,146,149,151,153,158,166,168,173,175,179,184,193,194,211,223,228,248,354,356,358,361,364] (snmp_verbosity:_/_)
         snmp_notification_mib.beam:[122,126,127,128,390,397] (snmp_conf:_/_)
         snmp_notification_mib.beam:[351,367,375,380,445,449,453] (snmp_generic:_/_)
         snmp_notification_mib.beam:286 (snmp_misc:_/_)
         snmp_notification_mib.beam:229 (snmp_target_mib:_/_)
         snmp_notification_mib.beam:[59,64,67,89,93,99,102,108,137,140,243,252,259,266,272,279,288,292] (snmp_verbosity:_/_)
         snmp_notification_mib.beam:434 (snmpa_agent:_/_)
         snmp_notification_mib.beam:476 (snmpa_error:_/_)
         snmp_notification_mib.beam:[62,138,139,145] (snmpa_local_db:_/_)
         snmp_notification_mib.beam:[150,153,187,348] (snmpa_mib_lib:_/_)
         snmp_notification_mib.beam:[207,211,221] (snmpa_target_cache:_/_)
         snmp_shadow_table.beam:119 (snmp_generic:_/_)
         snmp_shadow_table.beam:80 (snmp_misc:_/_)
         snmp_standard_mib.beam:[168,192,200,201,202,203,204,205,209] (snmp_conf:_/_)
         snmp_standard_mib.beam:[105,139,224,226,230,253,262,271,280,289,498,504,507,523,529,532,549,554,560,563,568,576] (snmp_generic:_/_)
         snmp_standard_mib.beam:[86,90,126,130,155] (snmp_verbosity:_/_)
         snmp_standard_mib.beam:[473,480] (snmpa:_/_)
         snmp_standard_mib.beam:[96,595] (snmpa_agent:_/_)
         snmp_standard_mib.beam:612 (snmpa_error:_/_)
         snmp_standard_mib.beam:[103,138,579,580,583,584,588,589,592] (snmpa_local_db:_/_)
         snmp_standard_mib.beam:[249,258,267,276,285,458,477,495,520] (snmpa_mib_lib:_/_)
         snmp_standard_mib.beam:220 (snmpa_mpd:_/_)
         snmp_target_mib.beam:[149,284,285,287,288,289,290,293,294,295,296,307,310,320,336,337,340,341,342,707,714,822,829,841,850,851,859,866,873,880,988,1015] (snmp_conf:_/_)
         snmp_target_mib.beam:[663,675,680,686,689,694,765,786,802,808,959,973,979,1049,1053,1057] (snmp_generic:_/_)
         snmp_target_mib.beam:[511,529,534] (snmp_misc:_/_)
         snmp_target_mib.beam:[131,776,972] (snmp_notification_mib:_/_)
         snmp_target_mib.beam:[81,87,91,114,118,124,126,128,130,136,270,297,351,356,462,489,496,499,509,513,517,526,532,536,540,546,551,579] (snmp_verbosity:_/_)
         snmp_target_mib.beam:1034 (snmpa_agent:_/_)
         snmp_target_mib.beam:1077 (snmpa_error:_/_)
         snmp_target_mib.beam:[85,353,354,358,359,364,370,609,652] (snmpa_local_db:_/_)
         snmp_target_mib.beam:[375,378,450,454,672,762,956] (snmpa_mib_lib:_/_)
         snmp_user_based_sm_mib.beam:[146,159,160,161,163,165,173,174,175,179,180,181,182,183,184,604,611,618,629,648,655,673,680,687] (snmp_conf:_/_)
         snmp_user_based_sm_mib.beam:[400,408,424,442,447,453,456,461,537,556,580,587,754,792,802,923,942,1068,1073,1098,1117,1139,1143,1147] (snmp_generic:_/_)
         snmp_user_based_sm_mib.beam:[1173,1189,1206] (snmp_misc:_/_)
         snmp_user_based_sm_mib.beam:[85,91,95,118,122,128,130,132,134,140,246,390,394,411,415,545,550,558,565,570,575,591,595,599] (snmp_verbosity:_/_)
         snmp_user_based_sm_mib.beam:1128 (snmpa_agent:_/_)
         snmp_user_based_sm_mib.beam:1254 (snmpa_error:_/_)
         snmp_user_based_sm_mib.beam:[89,247,248,253] (snmpa_local_db:_/_)
         snmp_user_based_sm_mib.beam:[263,266,309,320,326,332,338,344,350,439,534] (snmpa_mib_lib:_/_)
         snmp_usm.beam:[234,261] (crypto:block_decrypt/4)
         snmp_usm.beam:[219,251] (crypto:block_encrypt/4)
         snmp_usm.beam:[216,232] (snmp_misc:_/_)
         snmp_usm.beam:[157,190,236,263,279] (snmp_pdus:_/_)
         snmp_usm.beam:[181,206,225,239] (snmp_verbosity:_/_)
         snmp_view_based_acm_mib.beam:[140,147,148,149,155,156,157,158,161,162,163,164,172,173,175,177,475,484,674,713,720,727,950,957] (snmp_conf:_/_)
         snmp_view_based_acm_mib.beam:[360,362] (snmp_framework_mib:_/_)
         snmp_view_based_acm_mib.beam:[349,409,424,437,443,850,855,861,864,869,917,926,934,940,1053,1089,1094] (snmp_generic:_/_)
         snmp_view_based_acm_mib.beam:[78,84,88,111,115,121,123,128,186,191,195,200,416,421,430,435,447,451,455,470,479,488] (snmp_verbosity:_/_)
         snmp_view_based_acm_mib.beam:[255,269,286,295,308,322,359,423,661,925,1072] (snmpa_agent:_/_)
         snmp_view_based_acm_mib.beam:1139 (snmpa_error:_/_)
         snmp_view_based_acm_mib.beam:[82,187,188,196,197,209,230] (snmpa_local_db:_/_)
         snmp_view_based_acm_mib.beam:[236,239,333,337,407,547,847,915] (snmpa_mib_lib:_/_)
         snmp_view_based_acm_mib.beam:[192,222,285,296,342,552,576,741,751,754,757,766,769,778,790,799,1060] (snmpa_vacm:_/_)
         snmpa.beam:[895,902,918,923,940,944,962,965,984,987,1008,1012,1025,1036,1041,1047,1051,1056,1059,1063,1066,1070,1073,1076,1086] (snmp:_/_)
         snmpa.beam:1081 (snmp_log:_/_)
         snmpa.beam:830 (snmp_misc:_/_)
         snmpa.beam:[863,866,869] (snmp_standard_mib:_/_)
         snmpa.beam:[853,856] (snmp_usm:_/_)
         snmpa.beam:[176,177,178,179,180,184,186,188,190,196,198,271,272,274,275,279,298,303,304,324,336,356,368,372,378,564,567,570,573,580,587,594,601,608,613,618,625,632,639,646,666,672,678,684,689,695,808,818,821,839,846,1093,1106] (snmpa_agent:_/_)
         snmpa.beam:167 (snmpa_app:_/_)
         snmpa.beam:806 (snmpa_discovery_handler:_/_)
         snmpa.beam:[182,194] (snmpa_local_db:_/_)
         snmpa.beam:542 (snmpa_mib_lib:_/_)
         snmpa.beam:[181,192,208,212,215,218,221,228,231,234,237,240,243,246,249] (snmpa_symbolic_store:_/_)
         snmpa_acm.beam:138 (snmp_community_mib:_/_)
         snmpa_acm.beam:121 (snmp_conf:_/_)
         snmpa_acm.beam:121 (snmp_target_mib:_/_)
         snmpa_acm.beam:[126,134,144,170,179,247,323,331] (snmp_verbosity:_/_)
         snmpa_acm.beam:[283,348] (snmp_view_based_acm_mib:_/_)
         snmpa_acm.beam:248 (snmpa:_/_)
         snmpa_acm.beam:243 (snmpa_agent:_/_)
         snmpa_acm.beam:157 (snmpa_mpd:_/_)
         snmpa_acm.beam:[147,191] (snmpa_vacm:_/_)
         snmpa_agent.beam:[891,914,4246] (snmp_framework_mib:_/_)
         snmpa_agent.beam:[583,2913,2984,3999,4000,4009,4031,4071,4079,4163,4488,4491] (snmp_misc:_/_)
         snmpa_agent.beam:[4226,4356] (snmp_note_store:_/_)
         snmpa_agent.beam:3700 (snmp_pdus:_/_)
         snmpa_agent.beam:2315 (snmp_target_mib:_/_)
         snmpa_agent.beam:2483 (snmp_user_based_sm_mib:_/_)
         snmpa_agent.beam:[347,358,400,403,407,410,413,416,422,430,437,440,443,446,451,456,461,467,470,473,476,801,807,819,823,831,839,853,861,875,884,897,906,920,928,946,950,954,958,961,970,985,997,1009,1012,1020,1023,1030,1038,1041,1048,1062,1065,1072,1086,1089,1099,1112,1123,1130,1138,1146,1153,1167,1174,1190,1211,1217,1234,1239,1244,1249,1253,1257,1261,1268,1292,1306,1310,1323,1338,1349,1361,1366,1372,1377,1391,1392,1404,1580,1625,1629,1634,1637,1641,1645,1649,1656,1659,1758,1765,1773,1799,1828,1832,1843,1850,1860,1869,1883,1894,1900,1909,1916,1934,1942,1949,1953,1969,1991,2023,2056,2065,2071,2076,2089,2093,2097,2102,2109,2121,2125,2129,2134,2141,2158,2166,2173,2182,2187,2247,2255,2289,2297,2308,2346,2359,2367,2378,2385,2399,2418,2423,2433,2443,2453,2463,2468,2473,2481,2487,2532,2537,2539,2546,2552,2558,2563,2570,2575,2588,2598,2605,2711,2735,2813,2817,2856,2875,2890,2906,2925,2953,2960,2975,3188,3234,3254,3304,3345,3356,3626,3650,3661,3665,3669,3678,3702,3743,3769,3791,3830,3952,4091,4188,4192,4201] (snmp_verbosity:_/_)
         snmpa_agent.beam:[1175,1978,2739,3444] (snmpa_acm:_/_)
         snmpa_agent.beam:1885 (snmpa_agent:_/_)
         snmpa_agent.beam:[4416,4419] (snmpa_error:_/_)
         snmpa_agent.beam:[1640,4372] (snmpa_local_db:_/_)
         snmpa_agent.beam:[982,986,1202,1212,1219,1221,1235,1240,1245,1250,1254,1258,1314,1318,1448,1450,1452,1454,1456,1458,1460,1462,1464,1466,1469,1644,2494,2509,2677,3384,3386,3388,3496,4221,4231,4380] (snmpa_mib:_/_)
         snmpa_agent.beam:[405,434,465,1434,1435] (snmpa_misc_sup:_/_)
         snmpa_agent.beam:4388 (snmpa_mpd:_/_)
         snmpa_agent.beam:[2930,3400,3541,3841,3844] (snmpa_svbl:_/_)
         snmpa_agent.beam:[1648,4364] (snmpa_symbolic_store:_/_)
         snmpa_agent.beam:[1759,1811,1852,1862,2063,2151,2160,2253,2274,2352] (snmpa_trap:_/_)
         snmpa_agent.beam:1636 (snmpa_vacm:_/_)
         snmpa_agent_sup.beam:78 (snmpa_agent:_/_)
         snmpa_app.beam:121 (snmp_app_sup:_/_)
         snmpa_conf.beam:282 (snmp_community_mib:_/_)
         snmpa_conf.beam:[887,890,893] (snmp_config:_/_)
         snmpa_conf.beam:207 (snmp_framework_mib:_/_)
         snmpa_conf.beam:652 (snmp_notification_mib:_/_)
         snmpa_conf.beam:350 (snmp_standard_mib:_/_)
         snmpa_conf.beam:[476,505,587] (snmp_target_mib:_/_)
         snmpa_conf.beam:741 (snmp_user_based_sm_mib:_/_)
         snmpa_conf.beam:844 (snmp_view_based_acm_mib:_/_)
         snmpa_discovery_handler.beam:30 (snmp_misc:_/_)
         snmpa_error_logger.beam:49 (snmp_misc:_/_)
         snmpa_local_db.beam:[1014,1019,1020,1021,1024,1049,1063,1065,1076,1088,1089,1101,1102,1113,1114,1122,1130] (snmp_generic:_/_)
         snmpa_local_db.beam:1145 (snmp_misc:_/_)
         snmpa_local_db.beam:[137,152,155,166,169,203,205,345,349,354,376,381,387,392,397,406,411,419,424,433,438,445,450,458,463,467,478,483,486,491,501,517,526,530,535,540,546,551,557,565,572,577,587,597,598,607,617,628,666,671,674,677,683,691,695,702,707,715,717,719,721,724,878,885,899,1015] (snmp_verbosity:_/_)
         snmpa_local_db.beam:[1200,1203] (snmpa_error:_/_)
         snmpa_mib.beam:[920,926,929] (snmp_misc:_/_)
         snmpa_mib.beam:[279,280,312,317,322,324,335,347,360,364,368,371,386,391,399,406,412,417,423,434,438,443,445,450,461,465,479,486,505,513,522,529,537,542,552,562,569,582,594,605,620,629,633,642,643,652,662,672,678,847] (snmp_verbosity:_/_)
         snmpa_mib.beam:956 (snmpa_error:_/_)
         snmpa_mib_data_tttn.beam:[567,567] (snmp:_/_)
         snmpa_mib_data_tttn.beam:[156,157,277,511,524,1171] (snmp_misc:_/_)
         snmpa_mib_data_tttn.beam:[161,171,181,191,201,203,216,223,232,235,245,259,279,329,334,345,352,362,366,373,378,384,397,503,541,576,613,617,621,625,629,633,636,653,657,661,670,675,679,682,689,694,706,714,720,731,739,747,752,755,758,766,772,802,808,814,822,828,832,840,856,863,868,883,891,901,912,950,964,984,1015,1020,1023,1026,1030,1039,1050,1302,1312,1323,1370,1375,1405,1412] (snmp_verbosity:_/_)
         snmpa_mib_data_tttn.beam:[820,874,896,943,959,975] (snmpa_acm:_/_)
         snmpa_mib_data_tttn.beam:[346,353,374,1339,1340,1341,1342,1344,1381,1382,1383,1384,1385] (snmpa_symbolic_store:_/_)
         snmpa_mib_lib.beam:218 (snmp_generic:_/_)
         snmpa_mib_lib.beam:[163,169,176,195,241] (snmp_generic_mnesia:_/_)
         snmpa_mib_lib.beam:[43,46,51,54,68,72,75,80,224,231] (snmp_verbosity:_/_)
         snmpa_mib_lib.beam:247 (snmpa_error:_/_)
         snmpa_mib_lib.beam:[47,55,165,171,178,207,244] (snmpa_local_db:_/_)
         snmpa_mib_storage_dets.beam:[67,68,69,70] (snmp_misc:_/_)
         snmpa_mib_storage_dets.beam:[108,119,134,145,162,173,185,198,210,217,220,231,242,261,268,274,281,284] (snmp_verbosity:_/_)
         snmpa_mib_storage_ets.beam:[75,76] (snmp_misc:_/_)
         snmpa_mib_storage_ets.beam:[72,77,81,85,92,98,114,124,130,146,160,163,175,191,201,204,215,227,239,253,265,277,290,304] (snmp_verbosity:_/_)
         snmpa_mib_storage_ets.beam:342 (snmpa_error:_/_)
         snmpa_mib_storage_mnesia.beam:[276,279] (snmp_misc:_/_)
         snmpa_mib_storage_mnesia.beam:[65,71,74,83,90,93,116,127,141,158,169,187,205,229] (snmp_verbosity:_/_)
         snmpa_mpd.beam:223 (snmp_community_mib:_/_)
         snmpa_mpd.beam:[202,203,205,206,1118] (snmp_conf:_/_)
         snmpa_mpd.beam:[128,138,610,884,1205,1392] (snmp_framework_mib:_/_)
         snmpa_mpd.beam:[310,494,672,764,767,768,769,1208] (snmp_misc:_/_)
         snmpa_mpd.beam:[249,254,385,422,1050,1305] (snmp_note_store:_/_)
         snmpa_mpd.beam:[143,228,333,377,598,619,630,662,847,855,889,914,986] (snmp_pdus:_/_)
         snmpa_mpd.beam:1389 (snmp_target_mib:_/_)
         snmpa_mpd.beam:[77,147,155,163,172,177,182,244,265,289,299,312,320,325,335,351,380,397,409,434,446,467,471,512,561,570,574,587,592,645,685,721,728,758,784,812,901,1015,1029,1038,1053,1127,1132,1138,1144,1149,1156,1161,1166,1215,1245,1260,1270,1279,1285] (snmp_verbosity:_/_)
         snmpa_mpd.beam:[1521,1524] (snmpa_error:_/_)
         snmpa_net_if.beam:[292,1445] (snmp_conf:_/_)
         snmpa_net_if.beam:118 (snmp_framework_mib:_/_)
         snmpa_net_if.beam:[242,251,279,286,1350,1362,1372,1373] (snmp_log:_/_)
         snmpa_net_if.beam:[987,1020,1480,1490,1493,1496,1499,1502,1505,1508,1511,1514,1517,1520,1523,1526] (snmp_misc:_/_)
         snmpa_net_if.beam:[169,173,177,180,184,187,200,213,217,227,245,253,299,306,310,318,334,337,360,391,401,411,423,436,447,457,482,488,494,499,505,510,511,519,562,568,618,625,694,701,707,715,790,794,808,813,819,874,885,900,949,963,972,984,1002,1019,1024,1057,1073,1184,1188,1221,1343] (snmp_verbosity:_/_)
         snmpa_net_if.beam:[1540,1543] (snmpa_error:_/_)
         snmpa_net_if.beam:[203,459,683,871,904,967,1008] (snmpa_mpd:_/_)
         snmpa_net_if.beam:267 (snmpa_network_interface_filter:_/_)
         snmpa_network_interface_filter.beam:56 (snmp_misc:_/_)
         snmpa_notification_delivery_info_receiver.beam:36 (snmp_misc:_/_)
         snmpa_set.beam:[62,85,89,105,127,160] (snmp_verbosity:_/_)
         snmpa_set.beam:64 (snmpa_acm:_/_)
         snmpa_set.beam:[141,189,221] (snmpa_agent:_/_)
         snmpa_set.beam:245 (snmpa_error:_/_)
         snmpa_set.beam:[129,131,164,217] (snmpa_set_lib:_/_)
         snmpa_set.beam:[238,241] (snmpa_svbl:_/_)
         snmpa_set_lib.beam:179 (snmp_misc:_/_)
         snmpa_set_lib.beam:[81,86,146,161,174,184,191,197,204,231,408,410] (snmp_verbosity:_/_)
         snmpa_set_lib.beam:[354,356] (snmpa_agent:_/_)
         snmpa_set_lib.beam:[335,337,339] (snmpa_svbl:_/_)
         snmpa_supervisor.beam:[547,549] (snmp_framework_mib:_/_)
         snmpa_supervisor.beam:[332,654,657] (snmp_misc:_/_)
         snmpa_supervisor.beam:[183,185,188,193,200,205,210,215,219,224,322,331,336,341,346,364,379,392,397,404,409,416,422,425,435,441,447,474,479,490,494,522,532,542,544,546,548,550,552,554,558,562,567,571,574] (snmp_verbosity:_/_)
         snmpa_supervisor.beam:[95,121] (snmpa:_/_)
         snmpa_supervisor.beam:[167,170] (snmpa_agent_sup:_/_)
         snmpa_supervisor.beam:365 (snmpa_vacm:_/_)
         snmpa_svbl.beam:83 (snmp_pdus:_/_)
         snmpa_svbl.beam:52 (snmp_verbosity:_/_)
         snmpa_svbl.beam:53 (snmpa_mib:_/_)
         snmpa_symbolic_store.beam:[344,345,498,726,729] (snmp_misc:_/_)
         snmpa_symbolic_store.beam:[342,352,360,364,369,371,376,378,383,385,390,392,397,399,404,406,411,413,418,420,425,427,432,439,445,451,453,457,462,477,486,496,500,512,519,536,545,547,559,566,568,580,588,589,598,608,619,695,700] (snmp_verbosity:_/_)
         snmpa_symbolic_store.beam:750 (snmpa_error:_/_)
         snmpa_target_cache.beam:845 (snmp_misc:_/_)
         snmpa_target_cache.beam:[166,182,219,236,257,274,292,308,309,316,334,342,351,370,392,409,414,422,435,444,450,458,467,477,483,496,499,516,527,555,561,575,598] (snmp_verbosity:_/_)
         snmpa_target_cache.beam:865 (snmpa_error:_/_)
         snmpa_trap.beam:[707,728] (snmp_community_mib:_/_)
         snmpa_trap.beam:[347,352,639,826,944,993,1099] (snmp_framework_mib:_/_)
         snmpa_trap.beam:[484,487] (snmp_notification_mib:_/_)
         snmpa_trap.beam:[593,782] (snmp_standard_mib:_/_)
         snmpa_trap.beam:[502,521] (snmp_target_mib:_/_)
         snmpa_trap.beam:[134,142,150,373,399,404,483,486,489,509,527,555,576,665,669,692,705,712,719,726,733,741,748,756,762,770,783,797,809,832,850,858,870,880,885,920,931,946,960,982,1011,1020,1024,1030,1045,1051,1063,1073,1088,1093] (snmp_verbosity:_/_)
         snmpa_trap.beam:[402,1184,1195,1201,1213] (snmpa_acm:_/_)
         snmpa_trap.beam:[402,423,1213] (snmpa_agent:_/_)
         snmpa_trap.beam:1254 (snmpa_error:_/_)
         snmpa_trap.beam:263 (snmpa_mib:_/_)
         snmpa_trap.beam:[306,313] (snmpa_mpd:_/_)
         snmpa_trap.beam:[136,159,164] (snmpa_symbolic_store:_/_)
         snmpa_trap.beam:[644,675,987,1017,1035] (snmpa_trap:_/_)
         snmpa_trap.beam:1249 (snmpa_vacm:_/_)
         snmpa_usm.beam:[70,438,656,660,661,718,721] (snmp_framework_mib:_/_)
         snmpa_usm.beam:[166,197,391,492,579,611,738,753] (snmp_misc:_/_)
         snmpa_usm.beam:[79,399,588,618] (snmp_pdus:_/_)
         snmpa_usm.beam:[101,113,455,545] (snmp_user_based_sm_mib:_/_)
         snmpa_usm.beam:[625,628,631,634,638,662,670] (snmp_usm:_/_)
         snmpa_usm.beam:[77,90,96,100,111,118,132,135,142,149,163,168,185,192,224,230,232,246,263,273,287,297,312,329,346,350,353,359,365,373,379,403,417,429,445,465,479,488,505,514,525,555,581,584,587,590,594,617] (snmp_verbosity:_/_)
         snmpa_usm.beam:[698,701,704] (snmpa_agent:_/_)
         snmpa_vacm.beam:[66,74,84,93,100,108,122,215,227,236] (snmp_verbosity:_/_)
         snmpa_vacm.beam:[75,87,125,146,159] (snmp_view_based_acm_mib:_/_)
         snmpa_vacm.beam:448 (snmpa_error:_/_)
         snmpa_vacm.beam:80 (snmpa_mpd:_/_)
         snmpc.beam:169 (snmpc:_/_)
         snmpc.beam:[41,49,300,330,333,356,393,399,402,442,445,452,493,503,507,508,525,533,563,593,600,611,613,644,673,674,677,684,695,697,724,752,756,773,775,795,807,808,809,818,820,821,834,845,856,854,864,871,874,872,884,892,903,905,915,926,933,942,954,964,973,974,983,995,996,1017,1029,1041,1042,1063,1076,1088,1092,1099,1100,1108,1120,1132,1137,1144,1145,1153,1162,1177,1181,1182,1187,1189,1199,1204,1211,1211,1215,1217,1224,1243,1248,1254,1284,1297,1298,1301,1312,1317,1319,1343,1387,1398,1405,1410,1418,1424,1434,1440,1443,1471,1484,1490,1495,1512,1519,1523,1528,1544,1556,1573,1576] (snmpc_lib:_/_)
         snmpc.beam:1562 (snmpc_mib_gram:_/_)
         snmpc.beam:[52,55] (snmpc_mib_to_hrl:_/_)
         snmpc.beam:[129,243,1506,1507,1509,1510] (snmpc_misc:_/_)
         snmpc.beam:[1540,1547,1559] (snmpc_tok:_/_)
         snmpc_lib.beam:[412,413,659,837,873,889,929,931,952,960,965,970,974,977,980,986,1001,1005,1028,1042,1046,1055,1130,1134,1138,1150,1155,1200,1225,1228,1236,1248,1396,1409,1490,1492,1633,1643,1647,1657,1663,1667,1672,1710,1721,1731,1739,1749,1755,1760] (snmpc_lib:_/_)
         snmpc_lib.beam:[169,350,351,406,407,539,541,584,612,615,621,635,637,638,650,667,866,988,996,1338,1363,1487,1528,1540,1771] (snmpc_misc:_/_)
         snmpc_mib_gram.beam:[1035,1040,1046,1168,1184,1184] (snmpc_lib:_/_)
         snmpc_mib_gram.beam:1055 (snmpc_misc:_/_)
         snmpc_mib_to_hrl.beam:[48,54,59,65,77,79,85,94,100,104,113,118,124,132,145,156,230,266,333,352] (snmpc_lib:_/_)
         snmpc_mib_to_hrl.beam:[52,240,250] (snmpc_misc:_/_)
         snmpc_misc.beam:58 (snmp_misc:_/_)
         snmpm.beam:[822,828,844,849,866,870,888,891,910,913,934,937,950,961,965,971,975,980,983,987,990,994,997,1000,1005] (snmp:_/_)
         snmpm.beam:403 (snmp_conf:_/_)
         snmpm.beam:165 (snmp_config:_/_)
         snmpm.beam:[253,254,1029] (snmp_misc:_/_)
         snmpm.beam:[239,248,1245] (snmpm:_/_)
         snmpm.beam:[260,275,279,283,287,300,308,340,358,401,412,428,431,438,441,448,452,456,460,463,466,1023,1284,1287] (snmpm_config:_/_)
         snmpm.beam:[243,267,271,293,302,304,306,309,310,311,328,334,337,498,535,567,600,633,666,710,761,796,1009,1013,1017] (snmpm_server:_/_)
         snmpm.beam:[184,194,199] (snmpm_supervisor:_/_)
         snmpm_conf.beam:[349,352,355] (snmp_config:_/_)
         snmpm_conf.beam:[177,243,314] (snmpm_config:_/_)
         snmpm_config.beam:[304,1749,1794,1809,1850,1868,1893,1895,1897,1903,1906,1908,1919,1921,1927,2111,2119,2127,2140,2150,2168,2186,2196,2214,2263,2281,2286,2288,2292,2308,2310,2321,2336,2338,2344,2352,3017,3071,3321] (snmp_conf:_/_)
         snmpm_config.beam:[227,232,697,715,1086,1302,1440,2234,2491,3251,3253,3369,3373] (snmp_misc:_/_)
         snmpm_config.beam:[352,1033,1104,1128,1134,1153,1158,1161,1164,1179,1183,1197,1205,1210,1215,1226,1623,1692,1746,1797,1803,1825,1939,1944,1951,1959,1962,2025,2046,2347,2371,2385,2391,2399,2407,2417,2427,2433,2441,2450,2455,2460,2465,2475,2485,2490,2496,2501,2506,2511,2516,2531,2547,2578,2588,2604,2677,2682,2685,2688,2694,2702,2706,2713,2718,2723,2730,2733,2762,2773,2780,2786,2790,2794,2805,2835,2841,2851,2860,2874,2898,2913,2935,2943,2953,2963,2976,2985,3188,3221,3250] (snmp_verbosity:_/_)
         snmpm_mpd.beam:[167,168,873] (snmp_conf:_/_)
         snmpm_mpd.beam:[368,524,657,845,846,847,848] (snmp_misc:_/_)
         snmpm_mpd.beam:[301,327,550] (snmp_note_store:_/_)
         snmpm_mpd.beam:[103,180,256,291,478,504,597,649,734,784,813] (snmp_pdus:_/_)
         snmpm_mpd.beam:[70,79,124,133,139,145,158,178,182,189,196,216,231,237,244,248,260,266,294,296,305,310,319,348,356,365,390,456,468,473,500,522,535,537,539,545,553,596,619,688,693,812,872] (snmp_verbosity:_/_)
         snmpm_mpd.beam:[74,75,858,868,887,896,899,912,941,950,994] (snmpm_config:_/_)
         snmpm_mpd.beam:[928,945] (snmpm_usm:_/_)
         snmpm_net_if.beam:[324,468,1117] (snmp_conf:_/_)
         snmpm_net_if.beam:[416,425,453,454,470] (snmp_log:_/_)
         snmpm_net_if.beam:[815,875,1171] (snmp_misc:_/_)
         snmpm_net_if.beam:[255,260,272,277,280,292,308,313,398,401,419,427,489,494,499,504,508,513,530,541,549,570,581,586,633,705,711,759,765,771,776,781,785,792,799,865,937,940,979,1002,1006,1170] (snmp_verbosity:_/_)
         snmpm_net_if.beam:[245,252,258,263,266,275,279,402,403,404,405,408,1024,1046,1098,1114,1251,1255,1266] (snmpm_config:_/_)
         snmpm_net_if.beam:[259,697,861,934] (snmpm_mpd:_/_)
         snmpm_net_if.beam:385 (snmpm_network_interface_filter:_/_)
         snmpm_net_if_mt.beam:[324,468,666,828,910,1117] (snmp_conf:_/_)
         snmpm_net_if_mt.beam:[416,425,438,453,454,470] (snmp_log:_/_)
         snmpm_net_if_mt.beam:[815,875,1171] (snmp_misc:_/_)
         snmpm_net_if_mt.beam:[255,260,272,277,280,292,308,313,398,401,419,427,489,494,499,504,508,513,530,541,549,570,581,586,608,615,633,705,711,759,765,771,776,781,785,792,799,865,937,940,979,1002,1006,1170] (snmp_verbosity:_/_)
         snmpm_net_if_mt.beam:[245,252,258,263,266,275,279,402,403,404,405,408,1024,1046,1098,1114,1251,1255,1266] (snmpm_config:_/_)
         snmpm_net_if_mt.beam:[259,697,861,934] (snmpm_mpd:_/_)
         snmpm_net_if_mt.beam:385 (snmpm_network_interface_filter:_/_)
         snmpm_network_interface_filter.beam:55 (snmp_misc:_/_)
         snmpm_server.beam:[1374,1423,1479,1527,1603,2936,3297,3355] (snmp_misc:_/_)
         snmpm_server.beam:[945,3479] (snmp_note_store:_/_)
         snmpm_server.beam:3066 (snmp_pdus:_/_)
         snmpm_server.beam:[472,488,541,567,572,580,584,591,595,599,609,613,617,622,630,633,643,648,658,661,668,670,678,694,709,726,743,759,776,793,808,821,831,844,856,870,883,896,905,911,922,932,938,944,949,954,959,964,969,975,990,996,1001,1006,1012,1018,1024,1039,1047,1056,1064,1071,1107,1129,1139,1144,1149,1164,1182,1192,1197,1202,1218,1239,1251,1256,1261,1277,1296,1306,1311,1316,1332,1350,1359,1364,1381,1399,1408,1413,1430,1453,1464,1469,1485,1503,1512,1517,1534,1542,1548,1555,1560,1581,1586,1614,1627,1661,1676,1680,1691,1711,1750,1770,1788,1832,1847,1857,1868,1882,1915,1943,1961,1972,1987,2000,2022,2033,2037,2057,2078,2149,2163,2180,2190,2227,2249,2264,2279,2297,2315,2327,2346,2357,2369,2401,2427,2442,2458,2480,2499,2513,2517,2542,2551,2562,2572,2607,2642,2662,2677,2683,2696,2704,2722,2750,2764,2779,2800,2819,2832,2897,2913,2917,2922,2970,2981,3276] (snmp_verbosity:_/_)
         snmpm_server.beam:[214,535,538,544,559,573,574,592,660,663,669,912,914,923,925,1057,1073,1097,1635,1644,1693,1717,1719,1724,1736,1801,1812,1877,1885,1892,1917,2009,2045,2066,2178,2181,2193,2196,2229,2286,2304,2316,2353,2355,2366,2372,2403,2468,2487,2500,2558,2560,2575,2578,2609,2692,2694,2707,2725,2788,2807,2820,2908,2915,2919,2924,3082,3191,3239,3376,3379,3397,3459,3467] (snmpm_config:_/_)
         snmpm_server.beam:[578,593,1109,1110] (snmpm_misc_sup:_/_)
         snmpm_server.beam:3185 (snmpm_mpd:_/_)
         snmpm_server.beam:[3304,3310,3320,3325,3334,3338,3348,3351] (snmpm_server:_/_)
         snmpm_server_sup.beam:89 (snmp_misc:_/_)
         snmpm_supervisor.beam:94 (snmp_misc:_/_)
         snmpm_usm.beam:[141,261,340,365,389,476] (snmp_misc:_/_)
         snmpm_usm.beam:[71,272,371,395] (snmp_pdus:_/_)
         snmpm_usm.beam:[403,406,409,412,415,425,433] (snmp_usm:_/_)
         snmpm_usm.beam:[69,82,87,99,113,118,135,172,174,177,179,181,201,203,205,207,217,229,247,309,332,337,349,358] (snmp_verbosity:_/_)
         snmpm_usm.beam:[88,101,314,418,437,443,447,451,460,464,468,473,477,480,512,516,527] (snmpm_config:_/_)
         snmp_ex2_manager.beam:128 (snmp_config:_/_)
         snmp_ex2_manager.beam:[136,144,185,189,193,197,201,205,220] (snmpm:_/_)
         ssh.beam:[232,518,521] (ssh_acceptor:_/_)
         ssh.beam:[429,431] (ssh_client_channel:_/_)
         ssh.beam:[423,425] (ssh_connection:_/_)
         ssh.beam:[132,164,182,200,208,530] (ssh_connection_handler:_/_)
         ssh.beam:[124,128,131,153,157,158,159,163,224,226,229,230,272,281,282,284,460,516] (ssh_options:_/_)
         ssh.beam:[317,343,356,360,370,383,387] (ssh_system_sup:_/_)
         ssh.beam:447 (ssh_transport:_/_)
         ssh.beam:532 (sshd_sup:_/_)
         ssh_acceptor.beam:[128,132,136] (ssh_acceptor:_/_)
         ssh_acceptor.beam:152 (ssh_connection_handler:_/_)
         ssh_acceptor.beam:[57,58,72,80,87,94,95,142,145,151,153] (ssh_options:_/_)
         ssh_acceptor.beam:150 (ssh_subsystem_sup:_/_)
         ssh_acceptor.beam:[143,149] (ssh_system_sup:_/_)
         ssh_acceptor_sup.beam:84 (ssh_options:_/_)
         ssh_auth.beam:[148,500,514] (public_key:_/_)
         ssh_auth.beam:[196,448,486] (ssh_connection_handler:_/_)
         ssh_auth.beam:540 (ssh_message:_/_)
         ssh_auth.beam:558 (ssh_no_io:_/_)
         ssh_auth.beam:[97,104,124,140,141,194,348,413,415,464,492,495,501,502,512,513,544,545,546] (ssh_options:_/_)
         ssh_auth.beam:[110,128,146,147,169,170,173,188,199,215,228,231,253,262,282,287,307,311,326,370,379,399,426,430,434,444,520,520] (ssh_transport:_/_)
         ssh_channel.beam:[68,71,74,77,80,83,86,89,92] (ssh_client_channel:_/_)
         ssh_cli.beam:[88,94,110,139,145,146,147,226,227,441] (ssh_connection:_/_)
         ssh_cli.beam:[485,489,506,510,563,567] (ssh_connection_handler:_/_)
         ssh_cli.beam:643 (ssh_dbg:_/_)
         ssh_client_channel.beam:[256,270,293,308,381] (ssh_connection:_/_)
         ssh_client_channel.beam:[434,442,450,456] (ssh_dbg:_/_)
         ssh_connection.beam:[274,306,308,322,323,338,341,382,458,502,510,590,633,640,781,875,926,932,1176,1183,1201,1204,1213] (ssh_client_channel:_/_)
         ssh_connection.beam:[90,107,119,129,158,167,176,187,198,207,245,251,256,947] (ssh_connection_handler:_/_)
         ssh_connection.beam:[401,835,842,851] (ssh_options:_/_)
         ssh_connection.beam:824 (ssh_server_channel_sup:_/_)
         ssh_connection.beam:844 (ssh_sftpd:_/_)
         ssh_connection.beam:821 (ssh_subsystem_sup:_/_)
         ssh_connection_handler.beam:[736,783,797,814,823,889,917,926,944,1839] (ssh_auth:_/_)
         ssh_connection_handler.beam:[405,1098,1104,1112,1124,1167,1177,1184,1230,1248,1263,1274,1285,1288,1429,1426,1846,1861,1876,1989,2080,2142] (ssh_client_channel:_/_)
         ssh_connection_handler.beam:[993,1013,1046,1116,1126,1193,1223,1232,1244,1287,1406,1850,1864] (ssh_connection:_/_)
         ssh_connection_handler.beam:1649 (ssh_connection_sup:_/_)
         ssh_connection_handler.beam:1321 (ssh_message:_/_)
         ssh_connection_handler.beam:[143,387,404,410,422,424,424,425,446,448,452,462,473,477,481,489,961,966,1473,1493,1646,1648,1681,1700,1709,1904,1916,2095,2098,2104,2108,2123,2143,2157,2215,2262] (ssh_options:_/_)
         ssh_connection_handler.beam:1659 (ssh_system_sup:_/_)
         ssh_connection_handler.beam:[455,576,614,623,641,642,656,658,660,665,667,673,675,679,681,685,691,693,695,700,702,710,712,714,722,724,733,741,748,765,985,1308,1316,1698,1713,1720,1896] (ssh_transport:_/_)
         ssh_connection_handler.beam:131 (sshc_sup:_/_)
         ssh_daemon_channel.beam:[51,55] (ssh_server_channel:_/_)
         ssh_file.beam:[123,127,129,131,274,300,308] (public_key:_/_)
         ssh_file.beam:[209,213] (ssh_connection:_/_)
         ssh_file.beam:93 (ssh_transport:_/_)
         ssh_info.beam:115 (ssh_acceptor:_/_)
         ssh_info.beam:[87,152,163,240] (ssh_connection_handler:_/_)
         ssh_info.beam:[151,162] (ssh_server_channel:_/_)
         ssh_io.beam:[32,40,61] (ssh_options:_/_)
         ssh_message.beam:[261,287,295,472,502,515,613] (public_key:_/_)
         ssh_message.beam:[249,249,249,249,249,249,249,249,249,249,250,250,250,250,250,250,250,250,250,250,254,263,276,276,279,289,292,297] (ssh_bits:_/_)
         ssh_message.beam:[636,641,654,655,656,657,658,659,660,661,662,663,664,665,666,667,668,669,670,671,673,674,675,676,677,678,679,680,682,683,684,685,686,687,688,689,690,691,692,693,694,695] (ssh_dbg:_/_)
         ssh_no_io.beam:[34,41,47,53] (ssh_connection_handler:_/_)
         ssh_options.beam:527 (ssh:_/_)
         ssh_options.beam:[988,991,994,998] (ssh_options:_/_)
         ssh_options.beam:261 (ssh_sftpd:_/_)
         ssh_options.beam:[456,721,881,901,913,962,967,1019,1021,1024] (ssh_transport:_/_)
         ssh_server_channel.beam:[51,55] (ssh_client_channel:_/_)
         ssh_sftp.beam:[110,759,768,855] (ssh:_/_)
         ssh_sftp.beam:[126,154,823,832,880,899,947] (ssh_client_channel:_/_)
         ssh_sftp.beam:503 (ssh_connection:_/_)
         ssh_sftp.beam:1476 (ssh_dbg:_/_)
         ssh_sftp.beam:[124,152,564,588,593,601,610,624,645,667,680,698,703,708,714,719,724,729,734,739,744,750,817,889,904,959] (ssh_xfer:_/_)
         ssh_sftpd.beam:935 (ssh_connection:_/_)
         ssh_sftpd.beam:956 (ssh_dbg:_/_)
         ssh_sftpd.beam:[498,544,888] (ssh_sftp:_/_)
         ssh_sftpd.beam:[198,210,227,231,243,248,263,267,285,296,306,310,309,340,350,354,389,401,425,449,456,469,477,530,543,615,622,623,638,642,654,653,846,876,879,887] (ssh_xfer:_/_)
         ssh_shell.beam:[72,143,149] (ssh_connection:_/_)
         ssh_shell.beam:201 (ssh_dbg:_/_)
         ssh_system_sup.beam:61 (ssh_options:_/_)
         ssh_system_sup.beam:[108,112] (ssh_subsystem_sup:_/_)
         ssh_system_sup.beam:[91,95] (sshd_sup:_/_)
         ssh_transport.beam:[1610,1616,1622,1627] (crypto:block_decrypt/4)
         ssh_transport.beam:[1464,1470,1476,1482,2010] (crypto:block_encrypt/4)
         ssh_transport.beam:1946 (crypto:compute_key/4)
         ssh_transport.beam:1941 (crypto:generate_key/2)
         ssh_transport.beam:[1477,1483,1623,1628] (crypto:next_iv/2)
         ssh_transport.beam:[1260,1262] (crypto:sign/4)
         ssh_transport.beam:[1632,1636,1640] (crypto:stream_decrypt/2)
         ssh_transport.beam:[1487,1491,1495,2007] (crypto:stream_encrypt/2)
         ssh_transport.beam:[1412,1419,1426,1433,1440,1447,1556,1563,1570,1577,1584,1591,2007] (crypto:stream_init/3)
         ssh_transport.beam:[505,537,844,850,856,1264,1266,1267,1270,1274,1281,1282,1291,1292,1301,1302,1305,1816,1858,1865] (public_key:_/_)
         ssh_transport.beam:[267,454,478,598,631,676,704,1143,1151,1268,1268,1824,1824,1824,1829,1829,1829,1829,1829,1834,1834,1834,1834,1834] (ssh_bits:_/_)
         ssh_transport.beam:[335,352,459,482,488,515,547,553,564,603,608,635,641,646,681,708,714,728,1104] (ssh_connection_handler:_/_)
         ssh_transport.beam:2070 (ssh_dbg:_/_)
         ssh_transport.beam:[1118,1123] (ssh_message:_/_)
         ssh_transport.beam:[192,195,199,268,394,506,538,557,737,749,765,785,830,876,881,935,946] (ssh_options:_/_)
         ssh_xfer.beam:[61,70] (ssh:_/_)
         ssh_xfer.beam:[81,278,288,300,312,331,338,345] (ssh_connection:_/_)
         sshd_sup.beam:61 (ssh_acceptor_sup:_/_)
         sshd_sup.beam:[52,60] (ssh_system_sup:_/_)
         dtls.beam:[51,60,70,84,103,113] (ssl:_/_)
         dtls_connection.beam:73 (dtls_connection_sup:_/_)
         dtls_connection.beam:[250,308,318,434,499,506,522,551,555,569,685,833,939] (dtls_handshake:_/_)
         dtls_connection.beam:141 (dtls_packet_demux:_/_)
         dtls_connection.beam:[112,113,327,350,356,381,438,612,613,656,657,688,745,785,798,809,941,944,998] (dtls_record:_/_)
         dtls_connection.beam:[147,371,403,406,409,412,498,550] (dtls_socket:_/_)
         dtls_connection.beam:[453,457,899,901] (dtls_v1:_/_)
         dtls_connection.beam:[947,1127] (ssl_alert:_/_)
         dtls_connection.beam:[75,76,96,164,389,433,474,539,544,573,633,658,660,667,709,712,722,731,737,851,863,864,888,889,920,922,932,935,956,967,978] (ssl_connection:_/_)
         dtls_connection.beam:[293,333,510,526,993] (ssl_handshake:_/_)
         dtls_connection.beam:[300,349,1092] (ssl_record:_/_)
         dtls_handshake.beam:[74,102,182] (dtls_record:_/_)
         dtls_handshake.beam:[77,184,215,230,272,275,371] (dtls_v1:_/_)
         dtls_handshake.beam:197 (ssl_cipher:_/_)
         dtls_handshake.beam:[78,80,88,113,185,187,189,198,214,228,262,271,275,347,354,372] (ssl_handshake:_/_)
         dtls_handshake.beam:[75,90] (ssl_record:_/_)
         dtls_handshake.beam:83 (ssl_session:_/_)
         dtls_packet_demux.beam:237 (dtls_connection_sup:_/_)
         dtls_packet_demux.beam:236 (dtls_socket:_/_)
         dtls_record.beam:[383,514,531,551,573,601] (dtls_v1:_/_)
         dtls_record.beam:[516,533,552] (ssl_cipher:_/_)
         dtls_record.beam:[73,76,208,228,396,512,528,554,573,576,578] (ssl_record:_/_)
         dtls_socket.beam:38 (dtls_listener_sup:_/_)
         dtls_socket.beam:[49,86,95] (dtls_packet_demux:_/_)
         dtls_socket.beam:63 (ssl_connection:_/_)
         dtls_socket.beam:[85,94,97,99,102,104] (tls_socket:_/_)
         dtls_v1.beam:[34,39,41,45,47,78] (ssl_cipher:_/_)
         dtls_v1.beam:[36,50,53] (tls_v1:_/_)
         inet6_tls_dist.beam:[29,32,35,38,41,44,47] (inet_tls_dist:_/_)
         inet_tls_dist.beam:[347,434,458,477] (public_key:_/_)
         inet_tls_dist.beam:[121,124,141,158,169,175,242,254,266,429,431,527,534] (ssl:_/_)
         inet_tls_dist.beam:[178,407] (ssl_connection:_/_)
         ssl.beam:[237,297,684] (dtls_packet_demux:_/_)
         ssl.beam:[474,561,700,702] (dtls_record:_/_)
         ssl.beam:[127,168,404,408,577,615,686,817,1307] (dtls_socket:_/_)
         ssl.beam:[553,561,783] (dtls_v1:_/_)
         ssl.beam:[451,454,458,476,491,496,792,801,801,804,804,807,809,811,1326,1329,1332,1333,1344,1348,1352,1352] (ssl_cipher:_/_)
         ssl.beam:[217,229,238,254,280,287,295,310,313,323,341,355,373,390,420,438,575,609,674,717,732] (ssl_connection:_/_)
         ssl.beam:744 (ssl_pem_cache:_/_)
         ssl.beam:[471,558,699,701,800,803] (tls_record:_/_)
         ssl.beam:[108,109,112,125,166,228,230,239,247,248,252,252,253,256,406,410,588,625,658,661,682,688,814,1305] (tls_socket:_/_)
         ssl.beam:[537,550,917,1228,1235,1377] (tls_v1:_/_)
         ssl_app.beam:32 (ssl_sup:_/_)
         ssl_certificate.beam:[60,62,64,96,99,194,196,198,227,240,244,284,299,312,337,341,350,358] (public_key:_/_)
         ssl_certificate.beam:[77,107,116,224] (ssl_manager:_/_)
         ssl_certificate.beam:256 (ssl_pkix_db:_/_)
         ssl_cipher.beam:[227,231,235,237,300] (crypto:block_decrypt/4)
         ssl_cipher.beam:[135,139,143,145,165,172] (crypto:block_encrypt/4)
         ssl_cipher.beam:210 (crypto:stream_decrypt/2)
         ssl_cipher.beam:131 (crypto:stream_encrypt/2)
         ssl_cipher.beam:109 (crypto:stream_init/2)
         ssl_cipher.beam:[321,333,357] (dtls_v1:_/_)
         ssl_cipher.beam:[2249,2257] (public_key:_/_)
         ssl_cipher.beam:[2255,2882,2883,2894] (ssl_certificate:_/_)
         ssl_cipher.beam:[317,2431] (ssl_v3:_/_)
         ssl_cipher.beam:[319,2434] (tls_v1:_/_)
         ssl_config.beam:[114,124,129,134,139,140,157,167] (public_key:_/_)
         ssl_config.beam:[78,86] (ssl_certificate:_/_)
         ssl_config.beam:[44,47,64,107,164] (ssl_manager:_/_)
         ssl_config.beam:[45,48] (ssl_pem_cache:_/_)
         ssl_connection.beam:[2097,2126,2172,2183] (crypto:generate_key/2)
         ssl_connection.beam:[1478,1579] (pubkey_cert_records:_/_)
         ssl_connection.beam:[1577,1748,1772,1812,1833,2106,2135] (public_key:_/_)
         ssl_connection.beam:[612,664,688,705,801,804,812,843,896,911,931,960,989,1320,1503,1537,1614,1753,1777,1798,1817,1838,1860,1888,1901,1911,1921,1927,1935,1945,1957,1968,1981,1998,2019,2036,2078,2156,2477,2800] (ssl:_/_)
         ssl_connection.beam:[2728,2731,2743,2746] (ssl_alert:_/_)
         ssl_connection.beam:[529,878,1473,1484,1552,1566,2490,2525] (ssl_cipher:_/_)
         ssl_connection.beam:[571,2772] (ssl_config:_/_)
         ssl_connection.beam:[586,688,705,782,801,811,843,861,880,896,911,931,963,989,1195,1320,1503,1537,1557,1580,1600,1613,1656,1675,1680,1686,1695,1703,1710,1716,1729,1753,1777,1798,1817,1838,1860,1888,1911,1921,1927,1935,1945,1968,1981,1998,2020,2022,2036,2067,2078,2099,2108,2127,2137,2147,2156,2365,2366,2367,2368,2369,2370,2371,2372,2477,2502] (ssl_handshake:_/_)
         ssl_connection.beam:[2406,2447,2451,2752,2754] (ssl_manager:_/_)
         ssl_connection.beam:[2396,2404] (ssl_pkix_db:_/_)
         ssl_connection.beam:[693,710,732,1012,1305,1492,1750,1774,1795,1814,1835,1857,1885,2018,2053,2086,2088,2090,2092,2207,2215,2235,2238] (ssl_record:_/_)
         ssl_connection.beam:547 (ssl_session:_/_)
         ssl_connection.beam:2194 (ssl_srp_primes:_/_)
         ssl_connection.beam:1165 (tls_socket:_/_)
         ssl_crl.beam:[42,59,59,68,68,105,107] (public_key:_/_)
         ssl_crl.beam:[37,44,52] (ssl_certificate:_/_)
         ssl_crl.beam:[33,95] (ssl_pkix_db:_/_)
         ssl_crl_cache.beam:[71,84,141,149] (public_key:_/_)
         ssl_crl_cache.beam:[87,92,97,108] (ssl_manager:_/_)
         ssl_crl_cache.beam:[46,165] (ssl_pkix_db:_/_)
         ssl_crl_hash_dir.beam:[42,69,101] (public_key:_/_)
         ssl_dist_admin_sup.beam:66 (ssl_admin_sup:_/_)
         ssl_handshake.beam:[855,862,873] (crypto:compute_key/4)
         ssl_handshake.beam:1355 (crypto:private_encrypt/4)
         ssl_handshake.beam:[1347,1358] (crypto:sign/4)
         ssl_handshake.beam:2467 (pubkey_cert_records:_/_)
         ssl_handshake.beam:[161,350,395,397,403,406,848,920,922,1068,1087,1101,1103,1227,1349,1351,1360,1388,1398,1405,1408,1419,1425,1430,1453,2231,2462] (public_key:_/_)
         ssl_handshake.beam:[127,139,344,1249,1268,1276,1283] (ssl_certificate:_/_)
         ssl_handshake.beam:[179,542,542,618,618,695,695,772,772,776,780,1493,1494,1540,1548,1688,1689,1860,1860,1865,1865,1906,1906,1952,1952,2131,2459] (ssl_cipher:_/_)
         ssl_handshake.beam:1375 (ssl_crl:_/_)
         ssl_handshake.beam:1239 (ssl_pkix_db:_/_)
         ssl_handshake.beam:[102,419,429,496,1488,1490,1496,1522,1524,1534,2363,2371,2381,2393,2398,2400,2404,2408,2424,2446] (ssl_record:_/_)
         ssl_handshake.beam:823 (ssl_session:_/_)
         ssl_handshake.beam:870 (ssl_srp_primes:_/_)
         ssl_handshake.beam:[1463,1468,1501,1510] (ssl_v3:_/_)
         ssl_handshake.beam:[601,817,841,1064,1465,1470,1506,1513,1600,1626,1755,1792,1916] (tls_v1:_/_)
         ssl_manager.beam:512 (ssl_cipher:_/_)
         ssl_manager.beam:[91,103,130] (ssl_pem_cache:_/_)
         ssl_manager.beam:[115,126,142,226,286,291,330,335,370,400,528,530,531,532,617] (ssl_pkix_db:_/_)
         ssl_manager.beam:[423,431] (ssl_session:_/_)
         ssl_pem_cache.beam:99 (public_key:_/_)
         ssl_pem_cache.beam:[136,157,169,173,230] (ssl_pkix_db:_/_)
         ssl_pkix_db.beam:[151,164,304,307,350] (public_key:_/_)
         ssl_pkix_db.beam:[80,81,321] (ssl_pem_cache:_/_)
         ssl_record.beam:[307,324,340,372,401] (ssl_cipher:_/_)
         ssl_session.beam:[76,88] (ssl_manager:_/_)
         tls.beam:[50,59,69,83,102,112] (ssl:_/_)
         tls_connection.beam:746 (ssl_alert:_/_)
         tls_connection.beam:[82,83,95,96,116,160,178,199,206,221,224,227,366,408,437,441,459,464,477,500,502,577,580,587,594,603,606,688,689,715,716,731,733,755,766,777] (ssl_connection:_/_)
         tls_connection.beam:[240,249,251,295,414,737] (ssl_handshake:_/_)
         tls_connection.beam:304 (ssl_record:_/_)
         tls_connection.beam:[80,93] (tls_connection_sup:_/_)
         tls_connection.beam:[186,250,409,474,498,554,736] (tls_handshake:_/_)
         tls_connection.beam:[132,253,325,358,413,617,656,670,739,743] (tls_record:_/_)
         tls_connection.beam:[144,328,378,381,384,387] (tls_socket:_/_)
         tls_handshake.beam:[116,199] (ssl_cipher:_/_)
         tls_handshake.beam:[65,66,70,115,187,189,191,200,219,235,258,266,291,296,301] (ssl_handshake:_/_)
         tls_handshake.beam:[64,75] (ssl_record:_/_)
         tls_handshake.beam:71 (ssl_session:_/_)
         tls_handshake.beam:[62,101,118,119,185] (tls_record:_/_)
         tls_record.beam:[180,204,471] (ssl_cipher:_/_)
         tls_record.beam:[69,71,182,202,205,207,386,461,464,469,472] (ssl_record:_/_)
         tls_socket.beam:[71,85,100] (ssl_connection:_/_)
         tls_socket.beam:[183,185] (ssl_listen_tracker_sup:_/_)
         tls_socket.beam:69 (tls_connection_sup:_/_)
         tls_socket.beam:[66,82] (tls_socket:_/_)
         tls_v1.beam:407 (pubkey_cert_records:_/_)
         client_server.beam:[45,63] (public_key:_/_)
         client_server.beam:[33,34,41,42,44,47,48,50,52,60,62,64,67] (ssl:_/_)
         beam_lib.beam:943 (crypto:block_decrypt/4)
         c.beam:[259,356,374,428] (compile:file/2)
         erl_abstract_code.beam:10 (compile:noenv_forms/2)
         escript.beam:[204,323,331,339,658] (compile:forms/2)
         qlc_pt.beam:444 (compile:noenv_forms/2)
         merl.beam:335 (compile:noenv_forms/2)
         cover.beam:1523 (compile:file/2)
         cover.beam:1578 (compile:forms/2)
         make.beam:272 (compile:file/2)
     10: Dynamic creation of atoms can exhaust atom memory
         asn1ct.beam:1888 (file:consult/1)
         ct_config_plain.beam:29 (file:consult/1)
         ct_config_xml.beam:48 (xmerl_sax_parser:_/_)
         ct_cover.beam:95 (file:consult/1)
         ct_logs.beam:[1142,1836] (file:consult/1)
         ct_make.beam:[90,146] (file:consult/1)
         ct_netconfc.beam:1179 (xmerl:_/_)
         ct_netconfc.beam:1214 (xmerl_sax_parser:_/_)
         ct_release_test.beam:[380,796] (file:consult/1)
         ct_run.beam:3261 (file:consult/1)
         ct_snmp.beam:[123,456,472,487,503,518,533,548,564] (file:consult/1)
         ct_testspec.beam:332 (file:consult/1)
         ct_util.beam:[233,1006,1011] (file:consult/1)
         ct_webtool.beam:1139 (file:consult/1)
         test_server_ctrl.beam:[230,1270,5282] (file:consult/1)
         test_server_node.beam:161 (file:consult/1)
         test_server_sup.beam:[188,298,925] (file:consult/1)
         compile.beam:861 (file:consult/1)
         diameter_dbg.beam:146 (file:consult/1)
         edoc_data.beam:[116,516,527] (xmerl_lib:_/_)
         edoc_doclet.beam:[249,268,458] (xmerl:_/_)
         edoc_layout.beam:[99,1035,1060] (xmerl:_/_)
         edoc_wiki.beam:90 (xmerl_scan:_/_)
         docgen_edoc_xml_cb.beam:[42,48] (xmerl:_/_)
         docgen_otp_specs.beam:37 (xmerl:_/_)
         docgen_xmerl_xml_cb.beam:[53,56] (xmerl_lib:_/_)
         eunit_lib.beam:514 (file:path_consult/2)
         httpd.beam:58 (file:consult/1)
         httpd_sup.beam:144 (file:consult/1)
         inets.beam:240 (file:consult/1)
         hdlt.beam:41 (file:consult/1)
         erts_debug.beam:[421,452] (file:consult/1)
         inet_db.beam:276 (file:consult/1)
         net_adm.beam:50 (file:path_consult/2)
         megaco.beam:704 (file:consult/1)
         megaco_erl_dist_encoder.beam:[181,194,206,235,239,246,271] (erlang:binary_to_term/1)
         megaco_codec_transform.beam:95 (file:consult/1)
         observer_trace_wx.beam:1149 (file:consult/1)
         observer_wx.beam:497 (file:consult/1)
         reltool_server.beam:1433 (file:consult/1)
         dbg.beam:290 (file:consult/1)
         msacc.beam:94 (file:consult/1)
         system_information.beam:[530,694] (file:consult/1)
         release_handler.beam:[493,2071] (file:consult/1)
         release_handler.beam:526 (file:path_consult/2)
         systools_make.beam:[1802,1814] (file:consult/1)
         target_system.beam:39 (file:consult/1)
         snmp.beam:706 (file:consult/1)
         ssh_options.beam:768 (file:consult/1)
         beam_lib.beam:1115 (file:path_script/2)
         c.beam:693 (file:path_eval/2)
         make.beam:117 (file:consult/1)
         xref_parser.beam:283 (erlang:list_to_atom/1)
         sudoku_gui.beam:272 (file:consult/1)
         xmerl.beam:[163,169,180,183,206,209,265] (xmerl_lib:_/_)
         xmerl_eventp.beam:[163,174,209,218,242,251] (xmerl:_/_)
         xmerl_eventp.beam:[144,167,179,195,213,222,230,246,255,263,272,287,307,380,381,401,404,407] (xmerl_scan:_/_)
         xmerl_lib.beam:[470,472,474,476,479,481,483,485,488,490,492,494,498,500,502,504,507,509,511,513] (xmerl_ucs:_/_)
         xmerl_sax_parser.beam:[104,108] (xmerl_sax_parser_list:_/_)
         xmerl_scan.beam:[307,323,881,970,2459,2467,2476,2499,2506,2735,2993,3026,3066,3310,3418,3425,3745] (xmerl_lib:_/_)
         xmerl_scan.beam:[560,712] (xmerl_ucs:_/_)
         xmerl_scan.beam:2208 (xmerl_uri:_/_)
         xmerl_scan.beam:592 (xmerl_validate:_/_)
         xmerl_scan.beam:614 (xmerl_xsd:_/_)
         xmerl_simple.beam:[39,43,71,82,83,92,94,101,103,106,107] (xmerl_scan:_/_)
         xmerl_validate.beam:[234,300,319] (xmerl_lib:_/_)
         xmerl_xlate.beam:47 (xmerl:_/_)
         xmerl_xlate.beam:[42,46] (xmerl_scan:_/_)
         xmerl_xpath.beam:361 (xmerl_xpath_lib:_/_)
         xmerl_xpath.beam:225 (xmerl_xpath_parse:_/_)
         xmerl_xpath.beam:294 (xmerl_xpath_pred:_/_)
         xmerl_xpath.beam:224 (xmerl_xpath_scan:_/_)
         xmerl_xpath_lib.beam:[37,44] (xmerl_xpath_pred:_/_)
         xmerl_xpath_pred.beam:773 (xmerl_scan:_/_)
         xmerl_xpath_pred.beam:[136,292] (xmerl_xpath:_/_)
         xmerl_xpath_pred.beam:[790,802] (xmerl_xpath_scan:_/_)
         xmerl_xpath_scan.beam:[216,237,249] (xmerl_lib:_/_)
         xmerl_xs.beam:[97,100,118] (xmerl_lib:_/_)
         xmerl_xs.beam:109 (xmerl_xpath:_/_)
         xmerl_xsd.beam:[235,301,303,343,345,1951,1959] (xmerl_scan:_/_)
         xmerl_xsd.beam:[3393,3425] (xmerl_xpath:_/_)
         xmerl_xsd.beam:[184,191] (xmerl_xsd:_/_)
         xmerl_xsd.beam:[3206,5132] (xmerl_xsd_type:_/_)
         xmerl_xsd_type.beam:554 (xmerl_b64Bin:_/_)
         xmerl_xsd_type.beam:554 (xmerl_b64Bin_scan:_/_)
         xmerl_xsd_type.beam:[55,62,143,610,615,624,628,634,638,645] (xmerl_lib:_/_)
         xmerl_xsd_type.beam:[781,784] (xmerl_regexp:_/_)
         xmerl_xsd_type.beam:130 (xmerl_uri:_/_)
         xmerl_xsd_type.beam:[809,813,852,862,871,898,908,917,942,952,961,986,996,1005] (xmerl_xsd_type:_/_)

Module usage like the xmerl application using xmerl modules is redundant, but
the output may be used to understand how Erlang source code could have
security problems that are not reported by the pest.erl script when it is ran
on Erlang source code, due to an indirect function call.

If you want to include indirect function calls in the security scan pest.erl
performs, add each dependency that needs to be included in the scan with the
`-d` command line argument.  If you need to examine the resulting checks
after the dependencies are processed, but before the scan, add the `-i`
command line argument to display all the checks.  Below is the
resulting expanded checks after including Erlang/OTP indirect function calls
(4748 total lines that represent an exhaustive search for possible problems):

    $ ./pest.erl -v -b -d ~/installed/lib/erlang/lib/ -i
    [{90,"Port Drivers may cause undefined behavior",
      [{crashdump_viewer,debug,1},
       {ct_webtool,debug,1},
       {ct_webtool,debug_app,1},
       {dbg,trace_port,2},
       {dbg,trace_port1,3},
       {diameter_dbg,tracer,1},
       {erl_ddll,do_load_driver,3},
       {erl_ddll,load,2},
       {erl_ddll,load_driver,2},
       {erl_ddll,reload,2},
       {erl_ddll,reload_driver,2},
       {erl_ddll,try_load,3},
       {et_collector,monitor_trace_port,2},
       {et_collector,start_trace_port,1},
       {etop,start,0},
       {etop,start,1},
       {etop_tr,setup_tracer,1},
       {fprof,'$code_change',1},
       {fprof,analyse,0},
       {fprof,analyse,1},
       {fprof,analyse,2},
       {fprof,apply,2},
       {fprof,apply,3},
       {fprof,apply,4},
       {fprof,apply_1,3},
       {fprof,apply_1,4},
       {fprof,apply_continue,4},
       {fprof,apply_start_stop,4},
       {fprof,call,1},
       {fprof,handle_req,3},
       {fprof,load_profile,0},
       {fprof,load_profile,1},
       {fprof,load_profile,2},
       {fprof,open_dbg_trace_port,2},
       {fprof,profile,0},
       {fprof,profile,1},
       {fprof,profile,2},
       {fprof,save_profile,0},
       {fprof,save_profile,1},
       {fprof,save_profile,2},
       {fprof,server_loop,1},
       {fprof,start,0},
       {fprof,trace,1},
       {fprof,trace,2},
       {inets,enable_trace,2},
       {inets,enable_trace,3},
       {inets_trace,enable,2},
       {inets_trace,enable,3},
       {inets_trace,enable2,3},
       {megaco,enable_trace,2},
       {megaco_codec_meas,flex_scanner_handler,1},
       {megaco_codec_mstone_lib,flex_scanner_handler,1},
       {megaco_flex_scanner,do_start,1},
       {megaco_flex_scanner,load_driver,1},
       {megaco_flex_scanner,start,0},
       {megaco_flex_scanner,start,1},
       {megaco_flex_scanner_handler,bump_flex_scanner,1},
       {megaco_flex_scanner_handler,code_change,3},
       {megaco_flex_scanner_handler,init,1},
       {megaco_flex_scanner_handler,start_flex_scanners,0},
       {megaco_simple_mg,init_batch,4},
       {megaco_simple_mg,init_inline_trace,1},
       {megaco_simple_mg,start,0},
       {megaco_simple_mg,start,3},
       {megaco_simple_mgc,init_batch,3},
       {megaco_simple_mgc,init_inline_trace,1},
       {megaco_simple_mgc,start,0},
       {megaco_simple_mgc,start,2},
       {megaco_simple_mgc,start,4},
       {observer_trace_wx,handle_event,2},
       {test_server_node,add_nodes,3},
       {test_server_node,trc,1},
       {test_server_node,trc_loop,3},
       {ttb,do_tracer,3},
       {ttb,do_tracer,4},
       {ttb,ip_to_file,2},
       {ttb,start_trace,4},
       {ttb,tracer,0},
       {ttb,tracer,1},
       {ttb,tracer,2},
       {wxe_master,init,1}]},
     {90,"NIFs may cause undefined behavior",
      [{asn1rt_nif,load_nif,0},
       {crypto,on_load,0},
       {dyntrace,on_load,0},
       {erl_tracer,on_load,0},
       {erlang,load_nif,2},
       {init,boot,1},
       {prim_buffer,on_load,0},
       {prim_file,on_load,0},
       {zlib,on_load,0}]},
     {80,"OS shell usage may require input validation",
      [{cpu_sup,get_uint32_measurement,2},
       {cpu_sup,handle_call,3},
       {cpu_sup,init,1},
       {cpu_sup,measurement_server_init,0},
       {cpu_sup,measurement_server_loop,1},
       {cpu_sup,measurement_server_restart,1},
       {cpu_sup,measurement_server_start,0},
    ...4648 more lines...                ]}]

For comparison, the default checks specified in the pest.erl source code
are below (94 lines that represent [all core problems](https://github.com/okeuday/pest/blob/master/src/pest.erl#L153-L215)):

    $ ./pest.erl -v -i
    [{90,"Port Drivers may cause undefined behavior",
      [{erl_ddll,load,2},
       {erl_ddll,load_driver,2},
       {erl_ddll,reload,2},
       {erl_ddll,reload_driver,2},
       {erl_ddll,try_load,3}]},
     {90,"NIFs may cause undefined behavior",[{erlang,load_nif,2}]},
     {80,"OS shell usage may require input validation",[{os,cmd,1}]},
     {80,"OS process creation may require input validation",
      [{erlang,open_port,2}]},
     {15,"Keep OpenSSL updated for crypto module use (run with \"-V crypto\")",
      ['OTP-PUB-KEY','PKCS-FRAME',dtls,dtls_connection,dtls_connection_sup,
       dtls_handshake,dtls_listener_sup,dtls_packet_demux,dtls_record,dtls_socket,
       dtls_v1,inet6_tls_dist,inet_tls_dist,pubkey_cert,pubkey_cert_records,
       pubkey_crl,pubkey_pbe,pubkey_pem,pubkey_ssh,public_key,snmp,snmp_app,
       snmp_app_sup,snmp_community_mib,snmp_conf,snmp_config,snmp_framework_mib,
       snmp_generic,snmp_generic_mnesia,snmp_index,snmp_log,snmp_mini_mib,
       snmp_misc,snmp_note_store,snmp_notification_mib,snmp_pdus,
       snmp_shadow_table,snmp_standard_mib,snmp_target_mib,snmp_user_based_sm_mib,
       snmp_usm,snmp_verbosity,snmp_view_based_acm_mib,snmpa,snmpa_acm,
       snmpa_agent,snmpa_agent_sup,snmpa_app,snmpa_authentication_service,
       snmpa_conf,snmpa_discovery_handler,snmpa_discovery_handler_default,
       snmpa_error,snmpa_error_io,snmpa_error_logger,snmpa_error_report,
       snmpa_local_db,snmpa_mib,snmpa_mib_data,snmpa_mib_data_tttn,snmpa_mib_lib,
       snmpa_mib_storage,snmpa_mib_storage_dets,snmpa_mib_storage_ets,
       snmpa_mib_storage_mnesia,snmpa_misc_sup,snmpa_mpd,snmpa_net_if,
       snmpa_net_if_filter,snmpa_network_interface,snmpa_network_interface_filter,
       snmpa_notification_delivery_info_receiver,snmpa_notification_filter,
       snmpa_set,snmpa_set_lib,snmpa_set_mechanism,snmpa_supervisor,snmpa_svbl,
       snmpa_symbolic_store,snmpa_target_cache,snmpa_trap,snmpa_usm,snmpa_vacm,
       snmpc,snmpc_lib,snmpc_mib_gram,snmpc_mib_to_hrl,snmpc_misc,snmpc_tok,snmpm,
       snmpm_conf,snmpm_config,snmpm_misc_sup,snmpm_mpd,snmpm_net_if,
       snmpm_net_if_filter,snmpm_net_if_mt,snmpm_network_interface,
       snmpm_network_interface_filter,snmpm_server,snmpm_server_sup,
       snmpm_supervisor,snmpm_user,snmpm_user_default,snmpm_user_old,snmpm_usm,
       ssh,ssh_acceptor,ssh_acceptor_sup,ssh_app,ssh_auth,ssh_bits,ssh_channel,
       ssh_cli,ssh_client_channel,ssh_client_key_api,ssh_connection,
       ssh_connection_handler,ssh_connection_sup,ssh_daemon_channel,ssh_dbg,
       ssh_file,ssh_info,ssh_io,ssh_message,ssh_no_io,ssh_options,
       ssh_server_channel,ssh_server_channel_sup,ssh_server_key_api,ssh_sftp,
       ssh_sftpd,ssh_sftpd_file,ssh_sftpd_file_api,ssh_shell,ssh_subsystem_sup,
       ssh_sup,ssh_system_sup,ssh_transport,ssh_xfer,sshc_sup,sshd_sup,ssl,
       ssl_admin_sup,ssl_alert,ssl_app,ssl_certificate,ssl_cipher,ssl_config,
       ssl_connection,ssl_connection_sup,ssl_crl,ssl_crl_cache,ssl_crl_cache_api,
       ssl_crl_hash_dir,ssl_dist_admin_sup,ssl_dist_connection_sup,ssl_dist_sup,
       ssl_handshake,ssl_listen_tracker_sup,ssl_manager,ssl_pem_cache,ssl_pkix_db,
       ssl_record,ssl_session,ssl_session_cache,ssl_session_cache_api,
       ssl_srp_primes,ssl_sup,ssl_v3,tls,tls_connection,tls_connection_sup,
       tls_handshake,tls_record,tls_socket,tls_v1,
       {compile,file,2},
       {compile,forms,2},
       {compile,noenv_file,2},
       {compile,noenv_forms,2},
       {crypto,block_decrypt,3},
       {crypto,block_decrypt,4},
       {crypto,block_encrypt,3},
       {crypto,block_encrypt,4},
       {crypto,compute_key,4},
       {crypto,ec_curve,1},
       {crypto,generate_key,2},
       {crypto,generate_key,3},
       {crypto,next_iv,2},
       {crypto,next_iv,3},
       {crypto,private_decrypt,4},
       {crypto,private_encrypt,4},
       {crypto,public_decrypt,4},
       {crypto,public_encrypt,4},
       {crypto,sign,4},
       {crypto,stream_decrypt,2},
       {crypto,stream_encrypt,2},
       {crypto,stream_init,2},
       {crypto,stream_init,3},
       {crypto,verify,5}]},
     {10,"Dynamic creation of atoms can exhaust atom memory",
      [xmerl,xmerl_b64Bin,xmerl_b64Bin_scan,xmerl_eventp,xmerl_html,xmerl_lib,
       xmerl_otpsgml,xmerl_regexp,xmerl_sax_old_dom,xmerl_sax_parser,
       xmerl_sax_parser_latin1,xmerl_sax_parser_list,xmerl_sax_parser_utf16be,
       xmerl_sax_parser_utf16le,xmerl_sax_parser_utf8,xmerl_sax_simple_dom,
       xmerl_scan,xmerl_sgml,xmerl_simple,xmerl_text,xmerl_ucs,xmerl_uri,
       xmerl_validate,xmerl_xlate,xmerl_xml,xmerl_xpath,xmerl_xpath_lib,
       xmerl_xpath_parse,xmerl_xpath_pred,xmerl_xpath_scan,xmerl_xs,xmerl_xsd,
       xmerl_xsd_type,
       {erlang,binary_to_atom,2},
       {erlang,binary_to_term,1},
       {erlang,list_to_atom,1},
       {file,consult,1},
       {file,eval,1},
       {file,eval,2},
       {file,path_consult,2},
       {file,path_eval,2},
       {file,path_script,2},
       {file,path_script,3},
       {file,script,1},
       {file,script,2}]}]

See [Usage](#usage) for more information.

Indirect Security Concerns in Elixir
------------------------------------

To provide a representation of security concerns related to Elixir
dependencies, the pest.erl script was ran on all of the Elixir 1.6.6
installation beam files with the result provided below:

    $ ./pest.erl -v -b -D ErlangOTP/21.0 -p ~/installed/lib/elixir/lib/elixir/ebin ~/installed/lib/elixir/lib
     90: Port Drivers may cause undefined behavior
         Elixir.Mix.Tasks.Profile.Fprof.beam:182 (fprof:analyse/1)
         Elixir.Mix.Tasks.Profile.Fprof.beam:177 (fprof:apply/3)
         Elixir.Mix.Tasks.Profile.Fprof.beam:176 (fprof:profile/1)
     80: OS shell usage may require input validation
         Elixir.IEx.Introspection.beam:128 (os:cmd/1)
     80: OS process creation may require input validation
         Elixir.Code.beam:989 (beam_lib:chunks/2)
         Elixir.Collectable.File.Stream.beam:42 (file:open/2)
         Elixir.Enumerable.File.Stream.beam:78 (file:open/2)
         Elixir.Exception.beam:226 (beam_lib:chunks/2)
         Elixir.Exception.beam:[261,293] (erl_eval:expr/3)
         Elixir.File.beam:840 (file:copy/2)
         Elixir.File.beam:606 (file:copy/3)
         Elixir.File.beam:1256 (file:open/2)
         Elixir.File.beam:[919,929] (file:write_file/3)
         Elixir.GenEvent.beam:315 (gen:debug_options/2)
         Elixir.GenEvent.beam:347 (sys:handle_system_msg/7)
         Elixir.Kernel.Typespec.beam:356 (beam_lib:chunks/2)
         Elixir.Port.beam:181 (erlang:open_port/2)
         Elixir.Protocol.beam:260 (beam_lib:chunks/2)
         Elixir.Protocol.beam:315 (beam_lib:chunks/3)
         Elixir.Protocol.beam:501 (compile:forms/2)
         Elixir.Record.Extractor.beam:79 (epp:parse_file/2)
         Elixir.Record.Extractor.beam:114 (erl_eval:expr/2)
         Elixir.System.beam:629 (erlang:open_port/2)
         elixir.beam:233 (erl_eval:expr/5)
         elixir_compiler.beam:80 (beam_lib:chunks/2)
         elixir_erl.beam:13 (beam_lib:all_chunks/1)
         elixir_erl.beam:48 (beam_lib:chunks/2)
         elixir_erl.beam:33 (compile:noenv_forms/2)
         elixir_erl.beam:87 (erl_eval:expr/3)
         Elixir.IEx.CLI.beam:72 (erlang:open_port/2)
         Elixir.IEx.CLI.beam:57 (user:start/0)
         Elixir.IEx.Helpers.beam:1055 (compile:file/2)
         Elixir.IEx.Introspection.beam:160 (beam_lib:chunks/2)
         Elixir.IEx.Pry.beam:376 (beam_lib:chunks/2)
         Elixir.IEx.Pry.beam:410 (compile:noenv_forms/2)
         Elixir.Mix.Dep.Loader.beam:390 (file:consult/1)
         Elixir.Mix.Rebar.beam:50 (file:consult/1)
         Elixir.Mix.Rebar.beam:198 (file:script/2)
         Elixir.Mix.Shell.beam:102 (erlang:open_port/2)
         Elixir.Mix.Tasks.Compile.App.beam:161 (file:consult/1)
         Elixir.Mix.Tasks.Compile.Erlang.beam:104 (compile:file/2)
         Elixir.Mix.Tasks.Compile.Erlang.beam:147 (epp:parse_file/3)
         Elixir.Mix.Tasks.Compile.Leex.beam:62 (leex:file/2)
         Elixir.Mix.Tasks.Compile.Yecc.beam:62 (yecc:file/2)
         Elixir.Mix.Tasks.Escript.Build.beam:282 (beam_lib:all_chunks/1)
         Elixir.Mix.Tasks.Escript.Build.beam:290 (ram_file:open/2)
         Elixir.Mix.Tasks.Profile.Fprof.beam:182 (fprof:analyse/1)
         Elixir.Mix.Tasks.Profile.Fprof.beam:177 (fprof:apply/3)
         Elixir.Mix.Tasks.Profile.Fprof.beam:176 (fprof:profile/1)
         Elixir.Mix.Tasks.Test.Cover.beam:24 (cover:analyse_to_file/3)
         Elixir.Mix.Tasks.Test.Cover.beam:9 (cover:compile_beam_directory/1)
         Elixir.Mix.Tasks.Test.Cover.beam:23 (cover:modules/0)
         Elixir.Mix.Tasks.Test.Cover.beam:7 (cover:start/0)
         Elixir.Mix.Tasks.Xref.beam:343 (beam_lib:chunks/3)
     15: Keep OpenSSL updated for crypto module use (run with "-V crypto")
         Elixir.Code.beam:989 (beam_lib:chunks/2)
         Elixir.Exception.beam:226 (beam_lib:chunks/2)
         Elixir.Exception.beam:[261,293] (erl_eval:expr/3)
         Elixir.Kernel.Typespec.beam:356 (beam_lib:chunks/2)
         Elixir.Protocol.beam:260 (beam_lib:chunks/2)
         Elixir.Protocol.beam:315 (beam_lib:chunks/3)
         Elixir.Protocol.beam:501 (compile:forms/2)
         Elixir.Record.Extractor.beam:79 (epp:parse_file/2)
         Elixir.Record.Extractor.beam:114 (erl_eval:expr/2)
         elixir.beam:233 (erl_eval:expr/5)
         elixir_compiler.beam:80 (beam_lib:chunks/2)
         elixir_erl.beam:48 (beam_lib:chunks/2)
         elixir_erl.beam:33 (compile:noenv_forms/2)
         elixir_erl.beam:87 (erl_eval:expr/3)
         Elixir.IEx.CLI.beam:57 (user:start/0)
         Elixir.IEx.Helpers.beam:1055 (compile:file/2)
         Elixir.IEx.Introspection.beam:160 (beam_lib:chunks/2)
         Elixir.IEx.Pry.beam:376 (beam_lib:chunks/2)
         Elixir.IEx.Pry.beam:410 (compile:noenv_forms/2)
         Elixir.Mix.PublicKey.beam:[38,39,56] (public_key:_/_)
         Elixir.Mix.Rebar.beam:198 (file:script/2)
         Elixir.Mix.Tasks.Compile.Erlang.beam:104 (compile:file/2)
         Elixir.Mix.Tasks.Compile.Erlang.beam:147 (epp:parse_file/3)
         Elixir.Mix.Tasks.Compile.Yecc.beam:62 (yecc:file/2)
         Elixir.Mix.Tasks.Test.Cover.beam:24 (cover:analyse_to_file/3)
         Elixir.Mix.Tasks.Test.Cover.beam:9 (cover:compile_beam_directory/1)
         Elixir.Mix.Tasks.Test.Cover.beam:23 (cover:modules/0)
         Elixir.Mix.Tasks.Test.Cover.beam:7 (cover:start/0)
         Elixir.Mix.Tasks.Xref.beam:343 (beam_lib:chunks/3)
     10: Dynamic creation of atoms can exhaust atom memory
         Elixir.Code.Identifier.beam:198 (erlang:binary_to_atom/2)
         Elixir.Code.beam:991 (erlang:binary_to_term/1)
         Elixir.Kernel.CLI.beam:[389,400] (erlang:binary_to_atom/2)
         Elixir.Kernel.Typespec.beam:[807,810] (erlang:binary_to_atom/2)
         Elixir.Kernel.beam:[3362,3714,3674] (erlang:binary_to_atom/2)
         Elixir.List.beam:704 (erlang:list_to_atom/1)
         Elixir.Macro.beam:204 (erlang:binary_to_atom/2)
         Elixir.Module.beam:[757,798,741,730] (erlang:binary_to_atom/2)
         Elixir.Module.beam:1015 (erlang:list_to_atom/1)
         Elixir.OptionParser.beam:739 (erlang:binary_to_atom/2)
         Elixir.Protocol.beam:25 (erlang:binary_to_atom/2)
         Elixir.Record.Extractor.beam:39 (erlang:list_to_atom/1)
         Elixir.String.beam:2074 (erlang:binary_to_atom/2)
         Elixir.ExUnit.Callbacks.beam:469 (erlang:binary_to_atom/2)
         Elixir.ExUnit.Case.beam:[453,457] (erlang:binary_to_atom/2)
         Elixir.ExUnit.Filters.beam:[61,62] (erlang:binary_to_atom/2)
         Elixir.IEx.Autocomplete.beam:347 (erlang:binary_to_atom/2)
         Elixir.IEx.CLI.beam:160 (erlang:list_to_atom/1)
         Elixir.IEx.Helpers.beam:123 (erlang:binary_to_atom/2)
         Elixir.IEx.Introspection.beam:517 (erlang:binary_to_atom/2)
         Elixir.Logger.Formatter.beam:88 (erlang:binary_to_atom/2)
         Elixir.Mix.CLI.beam:125 (erlang:binary_to_atom/2)
         Elixir.Mix.Compilers.Elixir.beam:440 (erlang:binary_to_atom/2)
         Elixir.Mix.Compilers.Elixir.beam:[516,489,143] (erlang:binary_to_term/1)
         Elixir.Mix.Compilers.Erlang.beam:214 (erlang:binary_to_term/1)
         Elixir.Mix.Compilers.Test.beam:178 (erlang:binary_to_term/1)
         Elixir.Mix.Dep.ElixirSCM.beam:26 (erlang:binary_to_term/1)
         Elixir.Mix.Dep.Fetcher.beam:152 (erlang:binary_to_atom/2)
         Elixir.Mix.Dep.Loader.beam:390 (file:consult/1)
         Elixir.Mix.Dep.beam:457 (erlang:binary_to_atom/2)
         Elixir.Mix.Local.Installer.beam:[196,216,216] (erlang:binary_to_atom/2)
         Elixir.Mix.Rebar.beam:50 (file:consult/1)
         Elixir.Mix.Rebar.beam:198 (file:script/2)
         Elixir.Mix.State.beam:14 (erlang:binary_to_atom/2)
         Elixir.Mix.Task.beam:[195,273,101] (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.App.Start.beam:193 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.App.Tree.beam:48 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Cmd.beam:39 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Compile.App.beam:192 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Compile.App.beam:161 (file:consult/1)
         Elixir.Mix.Tasks.Compile.Erlang.beam:[98,229] (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Compile.Protocols.beam:176 (erlang:binary_to_term/1)
         Elixir.Mix.Tasks.Compile.Xref.beam:84 (erlang:binary_to_term/1)
         Elixir.Mix.Tasks.Deps.Clean.beam:38 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Deps.Get.beam:25 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Deps.Tree.beam:[39,49] (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Deps.Unlock.beam:54 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Deps.Update.beam:[44,64] (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Escript.Build.beam:169 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Format.beam:218 (erlang:binary_to_term/1)
         Elixir.Mix.Tasks.Xref.beam:353 (erlang:binary_to_term/1)

To cache all indirect security concerns for Elixir 1.6.6 using Erlang/OTP 21.0
the following command line was used:

    ./pest.erl -v -b -p ~/installed/lib/elixir/lib/elixir/ebin -d ~/installed/lib/elixir/lib -U pest/dependency/Elixir/1.6.6/21.0

To search an Elixir project's beam files for any indirect security concerns
related to the Elixir 1.6.6 source code and the Erlang/OTP 21.0 source code,
the command line arguments `-D ErlangOTP/21.0 -D Elixir/1.6.6/21.0` may be
added to the pest.erl command line to utilize these cached indirect security
concerns.

See [Usage](#usage) for more information.

Limitations
-----------

* All function calls that are checked use an Erlang atom for the module name
  and function name, so if a variable is used for either, it is possible that
  the function usage will not be seen by PEST.  If you are concerned about
  this problem, you can make sure optimizations are being used during
  compilation and confirm you are using PEST with the beam output of the
  compilation.

Updates
-------

Example command line use to update the cached data kept in `priv/pest.dat`
is shown below:

    ./pest.erl -v -b -d ~/installed/lib/erlang/lib/ -U pest/dependency/ErlangOTP/22.3.4.1
    ./pest.erl -v -b -d ~/installed/lib/erlang/lib/ -U pest/dependency/ErlangOTP/23.0.1
    ./pest.erl -U crypto

Author
------

Michael Truog (mjtruog at protonmail dot com)

License
-------

MIT License

