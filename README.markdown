[![Wyeomyia smithii](https://github.com/okeuday/pest/raw/master/images/320px-Wyeomyia_smithii.jpg)](https://en.wikipedia.org/wiki/Mosquito#Lifecycle)

Primitive Erlang Security Tool (PEST)
-------------------------------------

[![Build Status](https://secure.travis-ci.org/okeuday/pest.png?branch=master)](http://travis-ci.org/okeuday/pest)
[![hex.pm version](https://img.shields.io/hexpm/v/pest.svg)](https://hex.pm/packages/pest)

*CVEs* [Erlang](https://www.cvedetails.com/vendor/9446/Erlang.html) [OpenSSL](https://www.cvedetails.com/product/383/Openssl-Openssl.html?vendor_id=217) [PCRE](https://www.cvedetails.com/vendor/3265/Pcre.html) [zlib](https://www.cvedetails.com/vendor/13265/Zlib.html) [asmjit](https://github.com/asmjit/asmjit/issues) [ryu](https://github.com/ulfjack/ryu/issues)

Do a basic scan of Erlang source code and report any function calls that may
cause Erlang source code to be insecure.

The tool is provided in the form of an escript (an Erlang script) which may
also be used as a module.  Usage of the script is provided with the `-h`
command line argument, with the output shown below:

```
Usage pest.erl [OPTION] [FILES] [DIRECTORIES]

  -b              Only process beam files recursively
  -c              Perform internal consistency checks
  -d DEPENDENCY   Expand the checks to include a dependency
                  (provide the dependency as a file path or directory)
  -D IDENTIFIER   Expand the checks to include a dependency from an identifier
  -e              Only process source files recursively
  -E IDENTIFIER   Erase data associated with a dependency identifier
  -h              List available command line flags
  -i              Display checks information after expanding dependencies
  -L              List available dependency identifiers
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
```

Erlang/OTP version 21.0 and higher is required.
If beam files are used, they must have been compiled with the `debug_info`
option to provide the `abstract_code` used by pest.erl.  However, pest.erl
also consumes Erlang source code, including Erlang source escript files.
If beam files are available, it is best to use the beam files with pest.erl
due to how the Erlang compiler preprocessor and optimizations can influence
function calls.

Please feel free to contribute!  To add security problems to the scan
insert information into the [list of checks](https://github.com/okeuday/pest/blob/master/src/pest.erl#L153-L192).

Usage
-----

To scan any `.beam` files in a `lib` directory recursively, use:

    ./pest.erl -b /path_to_somewhere/lib

If you want to see all possible checks,
just turn on the verbose output with `-v`:

    ./pest.erl -vb /path_to_somewhere/lib

To check version information related to Erlang/OTP crypto, use:

    ./pest.erl -V crypto

To do a slower scan that includes indirect function calls from Erlang/OTP
(as described in [Indirect Security Concerns in Erlang/OTP](#indirect-security-concerns-in-erlangotp) and [Elixir](#indirect-security-concerns-in-elixir)), use:

    ./pest.erl -vb -d /erlang_install_prefix/lib/erlang/lib/ /path_to_somewhere/lib

Determining checks that include all indirect function calls for Erlang/OTP 23
can take several minutes, so it is easier to use cached results.
The checks have [already been cached](#updates) for Erlang/OTP 23.2.3,
which can be used to obtain the same output with:

    ./pest.erl -vb -D ErlangOTP/23.2.3 /path_to_somewhere/lib

If beam files created by an Elixir project need to be checked,
the following command line could be used:

    ./pest.erl -vb -D ErlangOTP/23.2.3 -D Elixir/1.11.3/23.2.3 -p ~/installed/lib/elixir/lib/elixir/ebin /path_to_somewhere/lib

The Elixir installation directory beam file path needs to be added to the
code search path for accessing an Elixir project's beam files
(the command line above is using the path
 `~/installed/lib/elixir/lib/elixir/ebin`).

Test
----

To have pest.erl check itself, use:

    ./pest.erl -vc -D ErlangOTP/23.2.3 ./pest.erl

Indirect Security Concerns in Erlang/OTP
----------------------------------------

Usage of various Erlang/OTP dependencies can have their own security concerns
which Erlang source code may depend on indirectly.  To provide a representation
of security concerns related to Erlang/OTP dependencies, the pest.erl script
was ran on all of the beam files installed for Erlang/OTP 23.2.3, with the
result provided below:

    $ ./pest.erl -vb ~/installed/lib/erlang/lib/
     90: Port Drivers may cause undefined behavior
         erl_ddll.beam:153 (erl_ddll:try_load/3)
         megaco_flex_scanner.beam:91 (erl_ddll:load_driver/2)
         dbg.beam:[440,447,478,485] (erl_ddll:load_driver/2)
         wxe_master.beam:125 (erl_ddll:load_driver/2)
     90: NIFs may cause undefined behavior
         asn1rt_nif.beam:[58,70] (erlang:load_nif/2)
         crypto.beam:[2541,2554] (erlang:load_nif/2)
         erl_tracer.beam:36 (erlang:load_nif/2)
         prim_buffer.beam:48 (erlang:load_nif/2)
         prim_file.beam:103 (erlang:load_nif/2)
         prim_net.beam:112 (erlang:load_nif/2)
         prim_socket.beam:371 (erlang:load_nif/2)
         zlib.beam:115 (erlang:load_nif/2)
         dyntrace.beam:[84,96] (erlang:load_nif/2)
     80: OS process creation may require input validation
         prim_inet.beam:93 (erlang:open_port/2)
         ram_file.beam:400 (erlang:open_port/2)
         megaco_flex_scanner.beam:116 (erlang:open_port/2)
         os_mon.beam:[89,95] (erlang:open_port/2)
     15: Keep OpenSSL updated for crypto module use (run with "-V crypto")
         ct_config.beam:[596,605,635,639] (crypto:_/_)
         ct_make.beam:285 (compile:file/2)
         ct_netconfc.beam:[1992,2065] (ssh:_/_)
         ct_netconfc.beam:[1024,2010,2012,2020,2023,2046,2055] (ssh_connection:_/_)
         ct_slave.beam:280 (ssh:_/_)
         ct_slave.beam:[281,283,287] (ssh_connection:_/_)
         ct_snmp.beam:[259,291,463,479,494,510,525,540,555,571] (snmp_config:_/_)
         ct_snmp.beam:[226,229] (snmpa:_/_)
         ct_snmp.beam:[97,102,110,111,347,371,379,384,390,395] (snmpm:_/_)
         ct_ssh.beam:443 (crypto:_/_)
         ct_ssh.beam:[444,447,719] (ssh:_/_)
         ct_ssh.beam:[474,479,487,502,505,524,532,545,553,737,742] (ssh_connection:_/_)
         ct_ssh.beam:[449,468,562,568,574,580,586,592,598,604,610,616,622,628,634,640,646,652,658,664,670,676,682,688,694,700,706,723] (ssh_sftp:_/_)
         compile.beam:[1590,1606,1608] (crypto:_/_)
         crypto.beam:[1643,1722,2443] (crypto:_/_)
         crypto.beam:[2724,2729,2775] (crypto_ec_curves:_/_)
         crypto_ec_curves.beam:6 (crypto:_/_)
         dialyzer_cl.beam:563 (compile:file/2)
         dialyzer_utils.beam:99 (compile:noenv_file/2)
         diameter_tcp.beam:[198,721,723,844,846,892,901] (ssl:_/_)
         eldap.beam:[513,585,625,963,1012,1017,1131,1133] (ssl:_/_)
         ftp.beam:[1599,2203,2221,2253,2302,2426,2429,2434] (ssl:_/_)
         http_transport.beam:[110,180,215,236,257,290,338,357,380,413,496] (ssl:_/_)
         httpc_handler.beam:1661 (ssl:_/_)
         httpd_script_env.beam:66 (ssl:_/_)
         hdlt_client.beam:211 (crypto:_/_)
         hdlt_client.beam:212 (ssl:_/_)
         hdlt_ctrl.beam:196 (crypto:_/_)
         hdlt_ctrl.beam:[198,302,421,992,1008] (ssh:_/_)
         hdlt_ctrl.beam:[295,330,336,342,353,366,415,444,450,456,471,985,1003,1012,1014,1020,1024,1026,1438,1458,1474,1485,1494] (ssh_sftp:_/_)
         hdlt_server.beam:149 (crypto:_/_)
         hdlt_server.beam:150 (ssl:_/_)
         hdlt_slave.beam:[153,221,226] (ssh:_/_)
         hdlt_slave.beam:[165,176] (ssh_connection:_/_)
         net_kernel.beam:1753 (crypto:_/_)
         OTP-PUB-KEY.beam:[1822,2101,2149,2230,2278,2439,2487,2924,2972,3019,3067,3114,3162,8644,8704,8848,8898,9354,9402,9431,9479,9653,9701,9730,9778,9807,9855,10016,10076,10151,10201,10306,10383,10466,10512,10636,10673,16767,16828,16885,16927,16984,17037,17062,17104,17190,17238,17327,17375,17508,17534,17579,17616,17747,17789] ('OTP-PUB-KEY':_/_)
         PKCS-FRAME.beam:[200,412,441,512,553,604,633,704,745,893,922,1044,1085,1144,1203,1295,1366,1412,1537,1714,1805] ('PKCS-FRAME':_/_)
         pubkey_cert.beam:618 ('OTP-PUB-KEY':_/_)
         pubkey_cert.beam:1315 (crypto:_/_)
         pubkey_cert.beam:1137 (pubkey_cert:_/_)
         pubkey_cert.beam:[80,1319] (pubkey_cert_records:_/_)
         pubkey_cert.beam:[537,542,565,608,610,613,1161,1288,1293,1309,1393,1396,1398,1400,1406] (public_key:_/_)
         pubkey_cert_records.beam:[40,231,244,289,303] ('OTP-PUB-KEY':_/_)
         pubkey_crl.beam:586 ('OTP-PUB-KEY':_/_)
         pubkey_crl.beam:[43,71,86,318,334,421,431,483,503,644,655,681] (pubkey_cert:_/_)
         pubkey_crl.beam:[287,316,332,344,383,388,391,399,705,710] (pubkey_cert_records:_/_)
         pubkey_crl.beam:[220,234,245,485,571,573,581,668,670,672] (public_key:_/_)
         pubkey_ocsp.beam:[223,336,338] (crypto:_/_)
         pubkey_ocsp.beam:[72,129,148,192,193,221,235,234,237,245,256,270,272,297,333] (public_key:_/_)
         pubkey_pbe.beam:[163,189,192,195,198,201,205,211] ('PKCS-FRAME':_/_)
         pubkey_pbe.beam:[42,45,48,51,54,57,66,69,72,75,78,81,92,151,157,186,261] (crypto:_/_)
         pubkey_pem.beam:[80,90,162,166] (pubkey_pbe:_/_)
         pubkey_pem.beam:[161,167] (public_key:_/_)
         pubkey_ssh.beam:[464,481,513,652] (public_key:_/_)
         public_key.beam:[286,357,1679,1721] ('OTP-PUB-KEY':_/_)
         public_key.beam:[277,349] ('PKCS-FRAME':_/_)
         public_key.beam:[427,448,470,498,538,546,548,549,553,554,555,556,557,558,566,567,571,593,602,685,715,1214,1245,1622,1648] (crypto:_/_)
         public_key.beam:[735,736,754,781,807,823,828,833,838,880,884,893,904,920,933,960,995,1263,1267,1279,1460,1467,1469,1471,1474,1478,1480,1487,1589,1591] (pubkey_cert:_/_)
         public_key.beam:[167,380,403,731,756,791,885,948,1628,1636,1642,1687] (pubkey_cert_records:_/_)
         public_key.beam:[792,858,1019,1027,1510,1524,1562,1569,1578] (pubkey_crl:_/_)
         public_key.beam:[1310,1311,1320,1885,1887,1893] (pubkey_ocsp:_/_)
         public_key.beam:[148,156,1398,1402] (pubkey_pem:_/_)
         public_key.beam:[505,521,1148,1171] (pubkey_ssh:_/_)
         public_key.beam:[730,1196,1203,1206] (public_key:_/_)
         snmp.beam:[264,267,270,273] (snmp_app:_/_)
         snmp.beam:276 (snmp_config:_/_)
         snmp.beam:[986,1015,1018] (snmp_log:_/_)
         snmp.beam:954 (snmp_misc:_/_)
         snmp.beam:[932,935] (snmp_pdus:_/_)
         snmp.beam:[943,946] (snmp_usm:_/_)
         snmp.beam:[916,921,1053,1055,1056,1057,1058,1059,1060,1061,1062,1064,1065,1066,1067,1068,1070,1071,1072,1073,1074,1075,1077,1079,1081,1084,1087,1089,1091,1093,1095,1096,1097,1100,1102,1104,1106] (snmpa:_/_)
         snmp.beam:[1041,1042,1045,1048,1051] (snmpc:_/_)
         snmp.beam:[918,923] (snmpm:_/_)
         snmp_app.beam:[39,117,141,153] (snmp_app_sup:_/_)
         snmp_app.beam:62 (snmpa_app:_/_)
         snmp_app_sup.beam:103 (snmp_misc:_/_)
         snmp_community_mib.beam:[138,147,148,149,150,151,473,480,487,494,501,569,576] (snmp_conf:_/_)
         snmp_community_mib.beam:[163,456] (snmp_framework_mib:_/_)
         snmp_community_mib.beam:[316,419,432,444,452,528,541,600,620] (snmp_generic:_/_)
         snmp_community_mib.beam:[265,301,355,359,550] (snmp_target_mib:_/_)
         snmp_community_mib.beam:[68,73,76,98,102,108,110,115,118,120,125,171,178,250,257,261,267,272,297,303] (snmp_verbosity:_/_)
         snmp_community_mib.beam:[445,586] (snmpa_agent:_/_)
         snmp_community_mib.beam:649 (snmpa_error:_/_)
         snmp_community_mib.beam:[71,116,117,174] (snmpa_local_db:_/_)
         snmp_community_mib.beam:[182,185,232,416] (snmpa_mib_lib:_/_)
         snmp_conf.beam:[146,154,203,213,220,232,242,246,249,254,258] (snmp_verbosity:_/_)
         snmp_config.beam:2116 (snmp_conf:_/_)
         snmp_config.beam:[1123,1172] (snmp_misc:_/_)
         snmp_config.beam:1841 (snmp_target_mib:_/_)
         snmp_config.beam:3024 (snmp_usm:_/_)
         snmp_config.beam:[1931,1934,1959,1962,1988,1991,2023,2026,2119,2122,2156,2159,2183,2186,2250,2253,2327,2330] (snmpa_conf:_/_)
         snmp_config.beam:[2412,2415,2434,2437,2456,2459,2477,2480] (snmpm_conf:_/_)
         snmp_framework_mib.beam:[126,136,145,182,209,224,248,271,273,297,299,316,319,337,339,342,389,391,393,402] (snmp_conf:_/_)
         snmp_framework_mib.beam:[423,534,542,546,566,570,574,577,580,583,626,632,638,647,649,653,678] (snmp_generic:_/_)
         snmp_framework_mib.beam:[659,671,681] (snmp_misc:_/_)
         snmp_framework_mib.beam:195 (snmp_target_mib:_/_)
         snmp_framework_mib.beam:[95,99,107,109,111,115,120,131,180,201,207,214,220,229,235,243,261,267,278,288,293,298,301,305,312,317,321,325,332,338,340,344,348,355,361,364,413,421,426,434] (snmp_verbosity:_/_)
         snmp_framework_mib.beam:[87,557] (snmpa_agent:_/_)
         snmp_framework_mib.beam:699 (snmpa_error:_/_)
         snmp_framework_mib.beam:[409,414,427,428,435,551] (snmpa_local_db:_/_)
         snmp_framework_mib.beam:[441,444,624,630,636,642] (snmpa_mib_lib:_/_)
         snmp_generic.beam:92 (snmp_generic:_/_)
         snmp_generic.beam:[61,65,70,105,117,123,128,196,202,508,602,818,825] (snmp_generic_mnesia:_/_)
         snmp_generic.beam:[100,107,213,216,234,237,242,246,249,253,425,445,734,736] (snmp_verbosity:_/_)
         snmp_generic.beam:918 (snmpa_error:_/_)
         snmp_generic.beam:[63,67,72,80,82,112,120,125,130,133,199,205,416,439,514,798,820,827] (snmpa_local_db:_/_)
         snmp_generic.beam:[742,749,757,764] (snmpa_symbolic_store:_/_)
         snmp_generic_mnesia.beam:[91,92,104,105,109,123,145,205,216,217,226,229,231,244,270,317,318,319,321,323,352,374,383] (snmp_generic:_/_)
         snmp_generic_mnesia.beam:402 (snmpa_error:_/_)
         snmp_index.beam:[55,60,65,71,78,87,100,111] (snmp_verbosity:_/_)
         snmp_log.beam:934 (snmp_conf:_/_)
         snmp_log.beam:[649,660,669,680] (snmp_mini_mib:_/_)
         snmp_log.beam:[798,857,1005,1023,1025] (snmp_misc:_/_)
         snmp_log.beam:[764,783,822,841,1008] (snmp_pdus:_/_)
         snmp_log.beam:[123,157,175,225,237,249,256,264,324,329,334,342,362,370,433,465,507,546,548,571,574,581,584,589,593,598,602,1062,1091,1100] (snmp_verbosity:_/_)
         snmp_mini_mib.beam:[60,62] (snmp_misc:_/_)
         snmp_misc.beam:226 (crypto:_/_)
         snmp_misc.beam:567 (snmp_mini_mib:_/_)
         snmp_misc.beam:[456,571] (snmp_misc:_/_)
         snmp_misc.beam:576 (snmp_pdus:_/_)
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
         snmp_standard_mib.beam:[169,193,201,202,203,204,205,206,210] (snmp_conf:_/_)
         snmp_standard_mib.beam:[106,140,225,227,231,254,263,272,281,290,499,505,508,524,530,533,550,557,563,566,571,579] (snmp_generic:_/_)
         snmp_standard_mib.beam:[87,91,127,131,156] (snmp_verbosity:_/_)
         snmp_standard_mib.beam:[474,481] (snmpa:_/_)
         snmp_standard_mib.beam:[97,598] (snmpa_agent:_/_)
         snmp_standard_mib.beam:615 (snmpa_error:_/_)
         snmp_standard_mib.beam:[104,139,582,583,586,587,591,592,595] (snmpa_local_db:_/_)
         snmp_standard_mib.beam:[250,259,268,277,286,459,478,496,521] (snmpa_mib_lib:_/_)
         snmp_standard_mib.beam:221 (snmpa_mpd:_/_)
         snmp_target_mib.beam:[150,285,286,288,289,290,291,294,295,296,297,308,311,321,337,338,341,342,343,710,717,825,832,844,853,854,862,869,876,883,991,1018] (snmp_conf:_/_)
         snmp_target_mib.beam:[664,676,683,689,692,697,768,789,805,811,962,976,982,1052,1056,1060] (snmp_generic:_/_)
         snmp_target_mib.beam:[512,530,535] (snmp_misc:_/_)
         snmp_target_mib.beam:[132,779,975] (snmp_notification_mib:_/_)
         snmp_target_mib.beam:[82,88,92,115,119,125,127,129,131,137,271,298,352,357,463,490,497,500,510,514,518,527,533,537,541,547,552,580] (snmp_verbosity:_/_)
         snmp_target_mib.beam:1037 (snmpa_agent:_/_)
         snmp_target_mib.beam:1080 (snmpa_error:_/_)
         snmp_target_mib.beam:[86,354,355,359,360,365,371,610,653] (snmpa_local_db:_/_)
         snmp_target_mib.beam:[376,379,451,455,673,765,959] (snmpa_mib_lib:_/_)
         snmp_user_based_sm_mib.beam:[1173,1190,1198] (crypto:_/_)
         snmp_user_based_sm_mib.beam:[146,159,160,161,163,165,173,174,175,179,180,181,182,183,184,606,613,620,631,650,657,675,682,689] (snmp_conf:_/_)
         snmp_user_based_sm_mib.beam:[400,408,424,442,449,455,458,463,539,558,582,589,756,794,804,925,944,1070,1075,1100,1119,1141,1145,1149] (snmp_generic:_/_)
         snmp_user_based_sm_mib.beam:[1175,1191,1208] (snmp_misc:_/_)
         snmp_user_based_sm_mib.beam:[85,91,95,118,122,128,130,132,134,140,246,390,394,411,415,547,552,560,567,572,577,593,597,601] (snmp_verbosity:_/_)
         snmp_user_based_sm_mib.beam:1130 (snmpa_agent:_/_)
         snmp_user_based_sm_mib.beam:1256 (snmpa_error:_/_)
         snmp_user_based_sm_mib.beam:[89,247,248,253] (snmpa_local_db:_/_)
         snmp_user_based_sm_mib.beam:[263,266,309,320,326,332,338,344,350,439,536] (snmpa_mib_lib:_/_)
         snmp_usm.beam:[83,92,94,98,104,106,110,165,179,198,206,224,239,256,266] (crypto:_/_)
         snmp_usm.beam:[221,237] (snmp_misc:_/_)
         snmp_usm.beam:[162,195,241,268,284] (snmp_pdus:_/_)
         snmp_usm.beam:[186,211,230,244] (snmp_verbosity:_/_)
         snmp_verbosity.beam:73 (snmp_misc:_/_)
         snmp_view_based_acm_mib.beam:[153,160,161,162,168,169,170,171,174,175,176,177,185,186,188,190,488,497,687,726,733,740,965,972] (snmp_conf:_/_)
         snmp_view_based_acm_mib.beam:[373,375] (snmp_framework_mib:_/_)
         snmp_view_based_acm_mib.beam:[362,422,437,450,456,863,870,876,879,884,932,941,949,955,1068,1104,1109] (snmp_generic:_/_)
         snmp_view_based_acm_mib.beam:[91,97,101,124,128,134,136,141,199,204,208,213,429,434,443,448,460,464,468,483,492,501] (snmp_verbosity:_/_)
         snmp_view_based_acm_mib.beam:[268,282,299,308,321,335,372,436,674,940,1087] (snmpa_agent:_/_)
         snmp_view_based_acm_mib.beam:1150 (snmpa_error:_/_)
         snmp_view_based_acm_mib.beam:[95,200,201,209,210,222,243] (snmpa_local_db:_/_)
         snmp_view_based_acm_mib.beam:[249,252,346,350,420,560,860,930] (snmpa_mib_lib:_/_)
         snmp_view_based_acm_mib.beam:[205,235,298,309,355,565,589,754,764,767,770,779,782,791,803,812,1075] (snmpa_vacm:_/_)
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
         snmpa_agent.beam:[920,943,3301] (snmp_framework_mib:_/_)
         snmpa_agent.beam:[612,3076,3077,3086,3108,3148,3156,3241,3552,3555] (snmp_misc:_/_)
         snmpa_agent.beam:[3281,3417] (snmp_note_store:_/_)
         snmpa_agent.beam:2378 (snmp_target_mib:_/_)
         snmpa_agent.beam:2546 (snmp_user_based_sm_mib:_/_)
         snmpa_agent.beam:[352,363,373,377,382,413,416,420,423,426,429,435,443,450,453,456,459,464,469,474,480,483,486,489,830,836,848,852,860,868,882,890,904,913,926,935,949,957,975,979,983,987,991,994,1003,1018,1030,1042,1045,1053,1056,1063,1071,1074,1081,1095,1098,1105,1119,1122,1132,1145,1156,1163,1171,1179,1186,1200,1207,1223,1244,1250,1267,1272,1277,1282,1286,1290,1294,1301,1325,1339,1343,1356,1371,1382,1394,1399,1405,1410,1424,1425,1441,1619,1622,1670,1674,1679,1682,1686,1690,1694,1701,1704,1803,1810,1818,1843,1871,1875,1888,1895,1905,1914,1928,1944,1950,1959,1966,1984,1992,1999,2003,2019,2041,2073,2106,2115,2121,2126,2142,2146,2150,2155,2162,2174,2178,2182,2187,2194,2211,2219,2226,2233,2242,2247,2307,2315,2352,2360,2371,2409,2422,2430,2441,2448,2462,2481,2486,2496,2506,2516,2526,2531,2536,2544,2550,2595,2600,2610,2617,2624,2630,2643,2650,2656,2671,2678,2696,2703,2910,3029,3168] (snmp_verbosity:_/_)
         snmpa_agent.beam:[1208,2028] (snmpa_acm:_/_)
         snmpa_agent.beam:1930 (snmpa_agent:_/_)
         snmpa_agent.beam:[3477,3480] (snmpa_error:_/_)
         snmpa_agent.beam:[1685,3433] (snmpa_local_db:_/_)
         snmpa_agent.beam:[1015,1019,1235,1245,1252,1254,1268,1273,1278,1283,1287,1291,1347,1351,1487,1489,1491,1493,1495,1497,1499,1501,1503,1505,1508,1689,2557,2572,2776,3276,3286,3441] (snmpa_mib:_/_)
         snmpa_agent.beam:[418,447,478,1473,1474] (snmpa_misc_sup:_/_)
         snmpa_agent.beam:3449 (snmpa_mpd:_/_)
         snmpa_agent.beam:[1693,3425] (snmpa_symbolic_store:_/_)
         snmpa_agent.beam:[1804,1855,1897,1907,2113,2204,2213,2313,2337,2415] (snmpa_trap:_/_)
         snmpa_agent.beam:1681 (snmpa_vacm:_/_)
         snmpa_agent_sup.beam:78 (snmpa_agent:_/_)
         snmpa_app.beam:123 (snmp_app_sup:_/_)
         snmpa_conf.beam:310 (snmp_community_mib:_/_)
         snmpa_conf.beam:[915,918,921] (snmp_config:_/_)
         snmpa_conf.beam:235 (snmp_framework_mib:_/_)
         snmpa_conf.beam:680 (snmp_notification_mib:_/_)
         snmpa_conf.beam:378 (snmp_standard_mib:_/_)
         snmpa_conf.beam:[504,533,615] (snmp_target_mib:_/_)
         snmpa_conf.beam:769 (snmp_user_based_sm_mib:_/_)
         snmpa_conf.beam:872 (snmp_view_based_acm_mib:_/_)
         snmpa_discovery_handler.beam:34 (snmp_misc:_/_)
         snmpa_error_logger.beam:49 (snmp_misc:_/_)
         snmpa_get.beam:288 (snmp_misc:_/_)
         snmpa_get.beam:1056 (snmp_pdus:_/_)
         snmpa_get.beam:[105,183,187,230,249,265,281,301,331,338,353,559,605,625,675,716,727,990,1014,1025,1029,1033,1042,1058,1099,1125,1144] (snmp_verbosity:_/_)
         snmpa_get.beam:810 (snmpa_acm:_/_)
         snmpa_get.beam:[160,274,290,350,442,736,867,910,937] (snmpa_agent:_/_)
         snmpa_get.beam:[82,111,159,166,269,289,305,343,423,431,452,455,511,731,789,807,882,905,914,920,924,940,945,998,1011,1021,1140,1143] (snmpa_get_lib:_/_)
         snmpa_get.beam:[755,757,759,864] (snmpa_mib:_/_)
         snmpa_get.beam:[306,771,909] (snmpa_svbl:_/_)
         snmpa_get_lib.beam:210 (snmp_misc:_/_)
         snmpa_get_lib.beam:[101,230,234,243] (snmp_verbosity:_/_)
         snmpa_get_lib.beam:107 (snmpa_acm:_/_)
         snmpa_get_lib.beam:252 (snmpa_error:_/_)
         snmpa_get_lib.beam:[153,192] (snmpa_svbl:_/_)
         snmpa_local_db.beam:[1015,1020,1021,1022,1025,1050,1064,1066,1077,1089,1090,1102,1103,1114,1115,1123,1131] (snmp_generic:_/_)
         snmpa_local_db.beam:[156,1146] (snmp_misc:_/_)
         snmpa_local_db.beam:[137,152,155,167,170,204,206,346,350,355,377,382,388,393,398,407,412,420,425,434,439,446,451,459,464,468,479,484,487,492,502,518,527,531,536,541,547,552,558,566,573,578,588,598,599,608,618,629,667,672,675,678,684,692,696,703,708,716,718,720,722,725,879,886,900,1016] (snmp_verbosity:_/_)
         snmpa_local_db.beam:[1201,1204] (snmpa_error:_/_)
         snmpa_mib.beam:[1015,1030,1033] (snmp_misc:_/_)
         snmpa_mib.beam:[292,293,326,331,336,338,350,362,375,379,383,386,401,406,414,421,427,432,440,444,449,455,460,465,472,483,487,492,494,499,510,514,528,535,554,562,571,578,586,591,601,611,618,631,643,654,669,678,682,691,692,701,711,735,918,923] (snmp_verbosity:_/_)
         snmpa_mib.beam:1060 (snmpa_error:_/_)
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
         snmpa_mib_storage_ets.beam:[72,77,81,85,92,98,114,124,130,146,160,163,175,191,202,205,216,230,242,256,268,280,293,307] (snmp_verbosity:_/_)
         snmpa_mib_storage_ets.beam:345 (snmpa_error:_/_)
         snmpa_mib_storage_mnesia.beam:[276,279] (snmp_misc:_/_)
         snmpa_mib_storage_mnesia.beam:[65,71,74,83,90,93,116,127,141,158,169,187,205,229] (snmp_verbosity:_/_)
         snmpa_mpd.beam:236 (snmp_community_mib:_/_)
         snmpa_mpd.beam:[215,216,218,219,1131] (snmp_conf:_/_)
         snmpa_mpd.beam:[126,136,623,897,1218,1405] (snmp_framework_mib:_/_)
         snmpa_mpd.beam:[323,507,685,777,780,781,782,1221] (snmp_misc:_/_)
         snmpa_mpd.beam:[262,267,398,435,1063,1318] (snmp_note_store:_/_)
         snmpa_mpd.beam:[141,241,346,390,611,632,643,675,860,868,902,927,999] (snmp_pdus:_/_)
         snmpa_mpd.beam:1402 (snmp_target_mib:_/_)
         snmpa_mpd.beam:[77,145,153,161,170,183,188,193,257,278,302,312,325,333,338,348,364,393,410,422,447,459,480,484,525,574,583,587,600,605,658,698,734,741,771,797,825,914,1028,1042,1051,1066,1140,1145,1151,1157,1162,1169,1174,1179,1228,1258,1273,1283,1292,1298] (snmp_verbosity:_/_)
         snmpa_mpd.beam:[1534,1537] (snmpa_error:_/_)
         snmpa_net_if.beam:[399,1994] (snmp_conf:_/_)
         snmpa_net_if.beam:200 (snmp_framework_mib:_/_)
         snmpa_net_if.beam:[349,358,386,393,1890,1902,1912,1913] (snmp_log:_/_)
         snmpa_net_if.beam:[1278,1312,2043,2053,2056,2059,2062,2065,2068,2071,2074,2077,2105,2104] (snmp_misc:_/_)
         snmpa_net_if.beam:[250,254,258,261,265,268,278,284,307,320,324,334,352,360,403,409,419,426,435,440,448,453,465,470,481,484,493,501,504,509,513,516,520,528,532,541,554,557,574,589,619,629,639,651,664,675,685,710,716,722,727,733,738,739,747,794,800,891,898,969,976,982,990,1083,1087,1101,1106,1112,1166,1177,1192,1240,1254,1263,1275,1293,1310,1317,1363,1375,1664,1668,1702,1718,1725,1734,1741,1746,1883,1985] (snmp_verbosity:_/_)
         snmpa_net_if.beam:[2126,2129] (snmpa_error:_/_)
         snmpa_net_if.beam:[310,687,958,1163,1196,1258,1299] (snmpa_mpd:_/_)
         snmpa_net_if.beam:374 (snmpa_network_interface_filter:_/_)
         snmpa_network_interface_filter.beam:56 (snmp_misc:_/_)
         snmpa_notification_delivery_info_receiver.beam:36 (snmp_misc:_/_)
         snmpa_set.beam:[62,85,89,105,127,160,166,169,195,203,210] (snmp_verbosity:_/_)
         snmpa_set.beam:64 (snmpa_acm:_/_)
         snmpa_set.beam:[141,193,230] (snmpa_agent:_/_)
         snmpa_set.beam:254 (snmpa_error:_/_)
         snmpa_set.beam:[129,131,164,226] (snmpa_set_lib:_/_)
         snmpa_set.beam:[247,250] (snmpa_svbl:_/_)
         snmpa_set_lib.beam:179 (snmp_misc:_/_)
         snmpa_set_lib.beam:[81,86,146,161,174,184,191,197,204,231,408,410] (snmp_verbosity:_/_)
         snmpa_set_lib.beam:[354,356] (snmpa_agent:_/_)
         snmpa_set_lib.beam:[335,337,339] (snmpa_svbl:_/_)
         snmpa_supervisor.beam:[588,590] (snmp_framework_mib:_/_)
         snmpa_supervisor.beam:[365,695,698] (snmp_misc:_/_)
         snmpa_supervisor.beam:[216,218,221,226,233,238,243,248,252,257,355,364,369,374,379,397,412,425,430,437,442,447,453,459,462,471,477,483,511,516,531,535,563,573,583,585,587,589,591,593,595,599,603,608,612,615] (snmp_verbosity:_/_)
         snmpa_supervisor.beam:[128,154] (snmpa:_/_)
         snmpa_supervisor.beam:[200,203] (snmpa_agent_sup:_/_)
         snmpa_supervisor.beam:398 (snmpa_vacm:_/_)
         snmpa_svbl.beam:83 (snmp_pdus:_/_)
         snmpa_svbl.beam:52 (snmp_verbosity:_/_)
         snmpa_svbl.beam:53 (snmpa_mib:_/_)
         snmpa_symbolic_store.beam:[344,345,498,726,729] (snmp_misc:_/_)
         snmpa_symbolic_store.beam:[342,352,360,364,369,371,376,378,383,385,390,392,397,399,404,406,411,413,418,420,425,427,432,439,445,451,453,457,462,477,486,496,500,512,519,536,545,547,559,566,568,580,588,589,598,608,619,695,700] (snmp_verbosity:_/_)
         snmpa_symbolic_store.beam:750 (snmpa_error:_/_)
         snmpa_target_cache.beam:845 (snmp_misc:_/_)
         snmpa_target_cache.beam:[166,182,219,236,257,274,292,308,309,316,334,342,351,370,392,409,414,422,435,444,450,458,467,477,483,496,499,516,527,555,561,575,598] (snmp_verbosity:_/_)
         snmpa_target_cache.beam:865 (snmpa_error:_/_)
         snmpa_trap.beam:[804,825] (snmp_community_mib:_/_)
         snmpa_trap.beam:[403,408,736,924,1060,1109,1215] (snmp_framework_mib:_/_)
         snmpa_trap.beam:[581,584] (snmp_notification_mib:_/_)
         snmpa_trap.beam:[690,879] (snmp_standard_mib:_/_)
         snmpa_trap.beam:[599,618] (snmp_target_mib:_/_)
         snmpa_trap.beam:[134,142,150,429,457,462,580,583,586,606,624,652,673,762,766,789,802,809,816,823,830,838,845,853,859,867,880,894,906,923,925,934,945,951,960,974,986,996,1001,1036,1047,1062,1076,1098,1127,1136,1140,1146,1161,1167,1179,1189,1204,1209] (snmp_verbosity:_/_)
         snmpa_trap.beam:[460,1300,1311,1317,1329] (snmpa_acm:_/_)
         snmpa_trap.beam:[460,481,1329] (snmpa_agent:_/_)
         snmpa_trap.beam:1370 (snmpa_error:_/_)
         snmpa_trap.beam:[307,317] (snmpa_mib:_/_)
         snmpa_trap.beam:[362,369] (snmpa_mpd:_/_)
         snmpa_trap.beam:[136,194] (snmpa_symbolic_store:_/_)
         snmpa_trap.beam:[741,772,1103,1133,1151] (snmpa_trap:_/_)
         snmpa_trap.beam:1365 (snmpa_vacm:_/_)
         snmpa_usm.beam:[71,439,667,729,732] (snmp_framework_mib:_/_)
         snmpa_usm.beam:[167,198,392,484,586,620,749,764] (snmp_misc:_/_)
         snmpa_usm.beam:[80,400,596,627] (snmp_pdus:_/_)
         snmpa_usm.beam:[102,114,456,547] (snmp_user_based_sm_mib:_/_)
         snmpa_usm.beam:[634,637,640,643,647,671,679] (snmp_usm:_/_)
         snmpa_usm.beam:[78,91,97,101,112,119,133,136,143,150,164,169,186,193,225,231,233,247,264,274,288,298,313,330,347,351,354,360,366,374,380,404,418,430,446,466,481,497,507,516,527,557,588,591,595,598,602,626] (snmp_verbosity:_/_)
         snmpa_usm.beam:[709,712,715] (snmpa_agent:_/_)
         snmpa_vacm.beam:[66,74,84,93,100,108,122,215,227,236] (snmp_verbosity:_/_)
         snmpa_vacm.beam:[75,87,125,146,159] (snmp_view_based_acm_mib:_/_)
         snmpa_vacm.beam:448 (snmpa_error:_/_)
         snmpa_vacm.beam:80 (snmpa_mpd:_/_)
         snmpc.beam:170 (snmpc:_/_)
         snmpc.beam:[42,50,297,327,330,353,390,396,399,441,444,451,492,502,506,507,524,532,562,592,599,610,612,643,672,673,676,683,694,696,723,751,755,772,774,794,806,807,808,817,819,820,833,844,855,853,863,870,873,871,883,891,902,904,914,925,932,941,953,963,972,973,982,994,995,1016,1028,1040,1041,1062,1075,1087,1091,1098,1099,1107,1119,1131,1136,1143,1144,1152,1161,1176,1180,1181,1186,1188,1198,1203,1210,1210,1214,1216,1223,1242,1247,1253,1283,1296,1297,1300,1311,1316,1318,1342,1386,1397,1404,1409,1417,1423,1433,1439,1442,1470,1483,1489,1494,1511,1518,1522,1527,1543,1555,1572,1575] (snmpc_lib:_/_)
         snmpc.beam:1561 (snmpc_mib_gram:_/_)
         snmpc.beam:[53,56] (snmpc_mib_to_hrl:_/_)
         snmpc.beam:[130,240,1505,1506,1508,1509] (snmpc_misc:_/_)
         snmpc.beam:[1539,1546,1558] (snmpc_tok:_/_)
         snmpc_lib.beam:[412,413,659,837,873,889,929,931,952,960,965,970,974,977,980,986,1001,1005,1028,1042,1046,1055,1130,1134,1138,1150,1155,1200,1225,1228,1236,1248,1396,1409,1490,1492,1633,1643,1647,1657,1663,1667,1672,1710,1721,1731,1739,1749,1755,1760] (snmpc_lib:_/_)
         snmpc_lib.beam:[169,350,351,406,407,539,541,584,612,615,621,635,637,638,650,667,866,988,996,1338,1363,1487,1528,1540,1771] (snmpc_misc:_/_)
         snmpc_mib_gram.beam:[1035,1040,1046,1168,1184,1184] (snmpc_lib:_/_)
         snmpc_mib_gram.beam:1055 (snmpc_misc:_/_)
         snmpc_mib_to_hrl.beam:[48,54,59,65,77,79,85,94,100,104,113,118,124,132,145,156,230,266,333,352] (snmpc_lib:_/_)
         snmpc_mib_to_hrl.beam:[52,240,250] (snmpc_misc:_/_)
         snmpc_misc.beam:58 (snmp_misc:_/_)
         snmpm.beam:[869,875,891,896,913,917,935,938,957,960,981,984,997,1008,1012,1018,1022,1027,1030,1034,1037,1041,1044,1047,1052] (snmp:_/_)
         snmpm.beam:465 (snmp_conf:_/_)
         snmpm.beam:209 (snmp_config:_/_)
         snmpm.beam:[302,303,1076] (snmp_misc:_/_)
         snmpm.beam:[288,297,1292] (snmpm:_/_)
         snmpm.beam:[309,324,328,332,336,352,360,402,420,463,474,490,493,500,503,510,514,518,522,525,528,1070,1331,1334] (snmpm_config:_/_)
         snmpm.beam:[292,316,320,342,354,356,358,361,362,363,373,390,396,399,560,597,629,662,695,728,764,808,843,1056,1060,1064] (snmpm_server:_/_)
         snmpm.beam:[228,238,247] (snmpm_supervisor:_/_)
         snmpm_conf.beam:[349,352,355] (snmp_config:_/_)
         snmpm_conf.beam:[177,243,314] (snmpm_config:_/_)
         snmpm_config.beam:[310,1780,1825,1840,1881,1899,1924,1926,1928,1934,1937,1939,1950,1952,1958,2143,2151,2159,2172,2182,2200,2218,2228,2246,2295,2313,2318,2320,2324,2340,2342,2353,2368,2370,2376,2384,3050,3104,3354] (snmp_conf:_/_)
         snmpm_config.beam:[233,238,697,715,1086,1306,1470,2266,2524,3284,3286,3402,3406] (snmp_misc:_/_)
         snmpm_config.beam:[358,1033,1104,1132,1138,1157,1162,1165,1168,1183,1187,1201,1209,1214,1219,1230,1653,1722,1777,1828,1834,1856,1970,1976,1983,1991,1994,2057,2078,2379,2404,2418,2424,2432,2440,2450,2460,2466,2474,2483,2488,2493,2498,2508,2518,2523,2529,2534,2539,2544,2549,2564,2580,2611,2621,2637,2710,2715,2718,2721,2727,2735,2739,2746,2751,2756,2763,2766,2795,2806,2813,2819,2823,2827,2838,2868,2874,2884,2893,2907,2931,2946,2968,2976,2986,2996,3009,3018,3221,3254,3283] (snmp_verbosity:_/_)
         snmpm_mpd.beam:[169,170,887] (snmp_conf:_/_)
         snmpm_mpd.beam:[370,526,659,847,848,849,850] (snmp_misc:_/_)
         snmpm_mpd.beam:[303,329,552] (snmp_note_store:_/_)
         snmpm_mpd.beam:[105,182,258,293,480,506,599,651,736,786,815] (snmp_pdus:_/_)
         snmpm_mpd.beam:[70,81,126,135,141,147,160,180,184,191,198,218,233,239,246,250,262,268,296,298,307,312,321,350,358,367,392,458,470,475,502,524,537,539,541,547,555,598,621,690,695,814,885] (snmp_verbosity:_/_)
         snmpm_mpd.beam:[76,77,860,870,875,884,901,910,913,926,955,964,1008] (snmpm_config:_/_)
         snmpm_mpd.beam:[942,959] (snmpm_usm:_/_)
         snmpm_net_if.beam:[332,484,1208] (snmp_conf:_/_)
         snmpm_net_if.beam:[432,441,469,470,486] (snmp_log:_/_)
         snmpm_net_if.beam:[907,967,1262] (snmp_misc:_/_)
         snmpm_net_if.beam:[263,268,280,285,288,300,316,321,414,417,435,443,505,510,515,520,524,529,536,553,564,572,578,600,613,624,629,639,646,725,797,803,851,857,863,868,873,877,884,891,957,1029,1032,1071,1093,1097,1261] (snmp_verbosity:_/_)
         snmpm_net_if.beam:[253,260,266,271,274,283,287,418,419,420,421,424,1115,1137,1189,1205,1342,1346,1357] (snmpm_config:_/_)
         snmpm_net_if.beam:[267,789,953,1026] (snmpm_mpd:_/_)
         snmpm_net_if.beam:401 (snmpm_network_interface_filter:_/_)
         snmpm_net_if_mt.beam:[332,484,758,920,1002,1208] (snmp_conf:_/_)
         snmpm_net_if_mt.beam:[432,441,454,469,470,486] (snmp_log:_/_)
         snmpm_net_if_mt.beam:[907,967,1262] (snmp_misc:_/_)
         snmpm_net_if_mt.beam:[263,268,280,285,288,300,316,321,414,417,435,443,505,510,515,520,524,529,536,553,564,572,578,600,613,624,629,639,646,700,707,725,797,803,851,857,863,868,873,877,884,891,957,1029,1032,1071,1093,1097,1261] (snmp_verbosity:_/_)
         snmpm_net_if_mt.beam:[253,260,266,271,274,283,287,418,419,420,421,424,1115,1137,1189,1205,1342,1346,1357] (snmpm_config:_/_)
         snmpm_net_if_mt.beam:[267,789,953,1026] (snmpm_mpd:_/_)
         snmpm_net_if_mt.beam:401 (snmpm_network_interface_filter:_/_)
         snmpm_network_interface_filter.beam:55 (snmp_misc:_/_)
         snmpm_server.beam:[1283,1332,1388,1436,1512,3065,3426,3484] (snmp_misc:_/_)
         snmpm_server.beam:[830,3885] (snmp_note_store:_/_)
         snmpm_server.beam:3195 (snmp_pdus:_/_)
         snmpm_server.beam:[335,348,402,451,456,464,468,475,479,483,494,498,502,507,515,518,528,533,543,546,553,555,563,579,594,611,628,644,661,678,693,706,716,729,741,755,768,781,790,796,807,817,823,829,834,839,844,849,854,860,871,882,888,893,898,904,910,916,931,938,947,955,962,1014,1038,1048,1053,1058,1073,1091,1101,1106,1111,1127,1148,1160,1165,1170,1186,1205,1215,1220,1225,1241,1259,1268,1273,1290,1308,1317,1322,1339,1362,1373,1378,1394,1412,1421,1426,1443,1451,1457,1464,1469,1490,1495,1523,1536,1570,1585,1589,1600,1620,1660,1682,1700,1744,1759,1769,1780,1794,1827,1855,1864,1889,1903,1916,1938,1949,1953,1973,1994,2065,2079,2096,2106,2143,2173,2186,2201,2219,2237,2249,2268,2279,2291,2323,2350,2363,2379,2401,2420,2434,2438,2463,2472,2483,2493,2528,2563,2583,2598,2604,2617,2625,2643,2672,2684,2699,2720,2739,2752,3026,3042,3046,3051,3099,3110,3405,3505,3548,3553,3564,3569,3575,3601,3608,3613,3620,3645,3652,3657,3663,3672,3675,3689] (snmp_verbosity:_/_)
         snmpm_server.beam:[245,396,399,405,410,432,439,457,458,476,545,548,554,797,799,808,810,948,964,1004,1544,1553,1602,1626,1628,1633,1645,1713,1724,1789,1797,1804,1829,1925,1961,1982,2094,2097,2109,2112,2149,2150,2151,2208,2226,2238,2275,2277,2288,2294,2325,2389,2408,2421,2479,2481,2496,2499,2530,2613,2615,2628,2646,2708,2727,2740,3037,3044,3048,3053,3211,3320,3368,3731,3742,3758,3761,3779,3865,3873] (snmpm_config:_/_)
         snmpm_server.beam:[462,477,1018,1019] (snmpm_misc_sup:_/_)
         snmpm_server.beam:3314 (snmpm_mpd:_/_)
         snmpm_server.beam:[2870,2876,2880,2885,3433,3439,3449,3454,3463,3467,3477,3480,3572,3579,3585,3589,3603,3616,3624,3629,3633,3647,3660,3682,3692,3698,3702] (snmpm_server:_/_)
         snmpm_server_sup.beam:89 (snmp_misc:_/_)
         snmpm_supervisor.beam:122 (snmp_misc:_/_)
         snmpm_usm.beam:[141,261,336,366,390,474] (snmp_misc:_/_)
         snmpm_usm.beam:[71,272,372,396] (snmp_pdus:_/_)
         snmpm_usm.beam:[404,407,410,413,416,424,431] (snmp_usm:_/_)
         snmpm_usm.beam:[69,82,87,99,113,118,135,172,174,177,179,181,201,203,205,207,217,229,247,310,333,345,350,359] (snmp_verbosity:_/_)
         snmpm_usm.beam:[88,101,315,419,435,441,445,449,458,462,466,471,475,478,510,514,525] (snmpm_config:_/_)
         snmp_ex2_manager.beam:128 (snmp_config:_/_)
         snmp_ex2_manager.beam:[136,144,185,189,193,197,201,205,220] (snmpm:_/_)
         ssh.beam:[288,765,768] (ssh_acceptor:_/_)
         ssh.beam:[520,522] (ssh_client_channel:_/_)
         ssh.beam:[510,512,515] (ssh_connection:_/_)
         ssh.beam:[199,209,256,264,599,608,654,700,786] (ssh_connection_handler:_/_)
         ssh.beam:[134,138,141,163,167,168,169,174,189,194,280,282,285,286,328,336,337,339,409,407,581,763,776] (ssh_options:_/_)
         ssh.beam:[193,390,403,451,464,468,478,491,495] (ssh_system_sup:_/_)
         ssh.beam:[99,101,568] (ssh_transport:_/_)
         ssh.beam:191 (sshc_sup:_/_)
         ssh.beam:788 (sshd_sup:_/_)
         ssh_acceptor.beam:[173,177,181] (ssh_acceptor:_/_)
         ssh_acceptor.beam:197 (ssh_connection_handler:_/_)
         ssh_acceptor.beam:[102,103,117,125,132,139,140,187,190,196,198] (ssh_options:_/_)
         ssh_acceptor.beam:195 (ssh_subsystem_sup:_/_)
         ssh_acceptor.beam:[74,188,194] (ssh_system_sup:_/_)
         ssh_acceptor_sup.beam:84 (ssh_options:_/_)
         ssh_agent.beam:[110,142] (ssh_agent:_/_)
         ssh_auth.beam:505 (crypto:_/_)
         ssh_auth.beam:[210,471,524] (ssh_connection_handler:_/_)
         ssh_auth.beam:[153,538,548,583] (ssh_message:_/_)
         ssh_auth.beam:612 (ssh_no_io:_/_)
         ssh_auth.beam:[101,103,110,129,208,372,438,440,487,495,498,530,533,586,587,588,626,751] (ssh_options:_/_)
         ssh_auth.beam:[144,151,152,177,180,181,539,549,554,554] (ssh_transport:_/_)
         ssh_bits.beam:63 (crypto:_/_)
         ssh_channel.beam:[69,72,75,78,81,84,87,90,93,96] (ssh_client_channel:_/_)
         ssh_channel_sup.beam:86 (ssh_options:_/_)
         ssh_cli.beam:[98,109,179,180,181,189,226,233,234,235,311,320,614,751] (ssh_connection:_/_)
         ssh_cli.beam:[658,662,679,683,726,731] (ssh_connection_handler:_/_)
         ssh_cli.beam:[862,883,897,914,921] (ssh_dbg:_/_)
         ssh_client_channel.beam:[257,271,294,309,382] (ssh_connection:_/_)
         ssh_client_channel.beam:[439,448,457,463] (ssh_dbg:_/_)
         ssh_connection.beam:[445,478,480,494,495,510,513,554,618,684,748,792,798,903,990,997,1120,1192,1243,1249,1496,1503,1525,1528,1537] (ssh_client_channel:_/_)
         ssh_connection.beam:[225,245,259,272,301,312,324,341,358,371,415,421,430,611,1264] (ssh_connection_handler:_/_)
         ssh_connection.beam:[573,669,915,921,1159,1168] (ssh_options:_/_)
         ssh_connection.beam:1161 (ssh_sftpd:_/_)
         ssh_connection.beam:[615,681,923,1139,1149] (ssh_subsystem_sup:_/_)
         ssh_connection.beam:925 (ssh_tcpip_forward_acceptor:_/_)
         ssh_connection_handler.beam:[2360,2361] (crypto:_/_)
         ssh_connection_handler.beam:[838,885,899,918,927,973,997,1025,1034,1056,2079] (ssh_auth:_/_)
         ssh_connection_handler.beam:[504,1217,1223,1231,1243,1298,1308,1315,1403,1428,1443,1454,1465,1468,1623,1620,1657,1659,2097,2112,2127,2272,2405,2467] (ssh_client_channel:_/_)
         ssh_connection_handler.beam:[1112,1132,1165,1235,1247,1248,1272,1338,1382,1389,1396,1405,1424,1467,1600,2101,2115] (ssh_connection:_/_)
         ssh_connection_handler.beam:1870 (ssh_connection_sup:_/_)
         ssh_connection_handler.beam:[706,2594] (ssh_dbg:_/_)
         ssh_connection_handler.beam:1514 (ssh_message:_/_)
         ssh_connection_handler.beam:[144,355,466,480,503,508,520,522,522,523,544,549,559,570,570,575,579,684,1076,1081,1374,1378,1413,1475,1693,1713,1866,1868,1887,1950,2160,2173,2264,2262,2420,2423,2429,2433,2448,2468,2482,2565,2603] (ssh_options:_/_)
         ssh_connection_handler.beam:[209,1658,1668] (ssh_subsystem_sup:_/_)
         ssh_connection_handler.beam:[1889,1891,1893,1895] (ssh_system_sup:_/_)
         ssh_connection_handler.beam:1668 (ssh_tcpip_forward_acceptor:_/_)
         ssh_connection_handler.beam:[552,673,712,721,743,744,758,760,762,767,769,775,777,781,783,787,793,795,797,802,804,812,814,816,824,826,835,843,850,867,1104,1499,1508,1948,1958,2088,2152] (ssh_transport:_/_)
         ssh_connection_handler.beam:1897 (sshc_sup:_/_)
         ssh_controller.beam:[88,94,107] (ssh_system_sup:_/_)
         ssh_daemon_channel.beam:[51,55] (ssh_server_channel:_/_)
         ssh_file.beam:[582,590] (public_key:_/_)
         ssh_file.beam:[246,250] (ssh_connection:_/_)
         ssh_file.beam:[136,262,576,761,785] (ssh_message:_/_)
         ssh_file.beam:[86,135,549] (ssh_transport:_/_)
         ssh_info.beam:115 (ssh_acceptor:_/_)
         ssh_info.beam:[87,158,174,251] (ssh_connection_handler:_/_)
         ssh_info.beam:173 (ssh_server_channel:_/_)
         ssh_io.beam:[32,40,61] (ssh_options:_/_)
         ssh_message.beam:[575,611,671,749] (public_key:_/_)
         ssh_message.beam:[241,241,241,241,241,241,241,241,241,241,242,242,242,242,242,242,242,242,242,242,246,255,268,268,271,281,571,571,573,573,573,573] (ssh_bits:_/_)
         ssh_message.beam:[781,791,809,810,811,812,813,814,815,816,817,818,819,820,821,822,823,824,825,826,828,829,830,831,832,833,834,835,837,838,839,840,841,842,843,844,845,846,847,848,849,850] (ssh_dbg:_/_)
         ssh_no_io.beam:[34,41,47,53] (ssh_connection_handler:_/_)
         ssh_options.beam:1010 (crypto:_/_)
         ssh_options.beam:680 (ssh:_/_)
         ssh_options.beam:269 (ssh_connection_handler:_/_)
         ssh_options.beam:[1143,1146,1149,1153,1154,1156] (ssh_options:_/_)
         ssh_options.beam:371 (ssh_sftpd:_/_)
         ssh_options.beam:[871,1036,1056,1068,1117,1122,1180,1182,1185] (ssh_transport:_/_)
         ssh_server_channel.beam:[51,55] (ssh_client_channel:_/_)
         ssh_sftp.beam:[150,206,1119,1128,1224] (ssh:_/_)
         ssh_sftp.beam:[1192,1201,1249,1268,1316] (ssh_client_channel:_/_)
         ssh_sftp.beam:[166,863] (ssh_connection:_/_)
         ssh_sftp.beam:168 (ssh_connection_handler:_/_)
         ssh_sftp.beam:1850 (ssh_dbg:_/_)
         ssh_sftp.beam:[924,948,953,961,970,984,1005,1027,1040,1058,1063,1068,1074,1079,1084,1089,1094,1099,1104,1110,1186,1258,1273,1328] (ssh_xfer:_/_)
         ssh_sftpd.beam:945 (ssh_connection:_/_)
         ssh_sftpd.beam:971 (ssh_dbg:_/_)
         ssh_sftpd.beam:[511,554,898] (ssh_sftp:_/_)
         ssh_sftpd.beam:[211,223,240,244,256,261,276,280,298,309,319,323,322,353,363,367,402,414,438,462,469,482,490,540,553,625,632,633,648,652,664,663,856,886,889,897] (ssh_xfer:_/_)
         ssh_shell.beam:[73,144,159] (ssh_connection:_/_)
         ssh_shell.beam:[254,270,276] (ssh_dbg:_/_)
         ssh_subsystem_sup.beam:61 (ssh_channel_sup:_/_)
         ssh_system_sup.beam:66 (ssh_options:_/_)
         ssh_system_sup.beam:[129,133] (ssh_subsystem_sup:_/_)
         ssh_system_sup.beam:104 (sshc_sup:_/_)
         ssh_system_sup.beam:[103,107] (sshd_sup:_/_)
         ssh_tcpip_forward_acceptor.beam:87 (ssh_connection:_/_)
         ssh_tcpip_forward_acceptor.beam:43 (ssh_tcpip_forward_acceptor_sup:_/_)
         ssh_tcpip_forward_client.beam:[43,50] (ssh_connection:_/_)
         ssh_tcpip_forward_srv.beam:[43,50] (ssh_connection:_/_)
         ssh_transport.beam:[284,855,1406,1408,1590,1612,1615,1617,1619,1629,1634,1672,1694,1699,1700,1700,1704,1719,1724,1861,1863,1865,1867,1869,1871,1888,1896,1901,2064,2066,2067,2067,2071,2072,2105] (crypto:_/_)
         ssh_transport.beam:[549,581,897,903,909,915,921,1410,1412,1413,1416,1420,1427,1428,1437,1438,1447,1448,1451,1960,1974] (public_key:_/_)
         ssh_transport.beam:[310,498,522,643,676,722,750,1242,1255,1265,1414,1414,1914,1918,1918,1918,1923,1923,1923,1923,1923,1928,1928,1928,1928,1928] (ssh_bits:_/_)
         ssh_transport.beam:[378,395,503,526,532,559,591,597,608,648,653,680,686,691,727,754,760,774,1197] (ssh_connection_handler:_/_)
         ssh_transport.beam:2186 (ssh_dbg:_/_)
         ssh_transport.beam:[1211,1216,1905] (ssh_message:_/_)
         ssh_transport.beam:[99,107,252,255,264,311,437,550,582,601,783,795,810,841,842,884,929,959,1015,1026] (ssh_options:_/_)
         ssh_xfer.beam:[246,256,268,280,299,306,313] (ssh_connection:_/_)
         sshc_sup.beam:[60,70] (ssh_controller:_/_)
         sshc_sup.beam:49 (ssh_system_sup:_/_)
         sshd_sup.beam:61 (ssh_acceptor_sup:_/_)
         sshd_sup.beam:[52,60] (ssh_system_sup:_/_)
         dtls_connection.beam:[179,186,187,222,228,283,284,315,319,387,389,455,457,519,522,524,541,543,631,634,677,680,699,710,777] (dtls_gen_connection:_/_)
         dtls_connection.beam:[212,274,281,306,348,352,370,513,649] (dtls_handshake:_/_)
         dtls_connection.beam:[218,416,417,476,477,516,585,724,775] (dtls_record:_/_)
         dtls_connection.beam:[273,347] (dtls_socket:_/_)
         dtls_connection.beam:[233,237] (dtls_v1:_/_)
         dtls_connection.beam:[164,231,240,250,290,330,372,542,548,570,576,652,670,693,704,715,780,782] (ssl_gen_statem:_/_)
         dtls_connection.beam:[184,287,311,617] (ssl_handshake:_/_)
         dtls_connection.beam:779 (ssl_logger:_/_)
         dtls_connection.beam:[216,757] (ssl_record:_/_)
         dtls_connection.beam:[211,512] (ssl_session:_/_)
         dtls_connection.beam:[271,324,374,551,561,639] (tls_dtls_connection:_/_)
         dtls_connection.beam:305 (tls_handshake:_/_)
         dtls_gen_connection.beam:81 (dtls_connection_sup:_/_)
         dtls_gen_connection.beam:[342,386,399,573] (dtls_handshake:_/_)
         dtls_gen_connection.beam:134 (dtls_packet_demux:_/_)
         dtls_gen_connection.beam:[105,106,410,440,445,575,578,593,591,608] (dtls_record:_/_)
         dtls_gen_connection.beam:[142,467,477,479,482,485,488] (dtls_socket:_/_)
         dtls_gen_connection.beam:[547,549] (dtls_v1:_/_)
         dtls_gen_connection.beam:618 (ssl_alert:_/_)
         dtls_gen_connection.beam:[83,84,160,327,332,498,535,552,625,627,638,641] (ssl_gen_statem:_/_)
         dtls_gen_connection.beam:[421,583] (ssl_handshake:_/_)
         dtls_gen_connection.beam:[255,275,276,298,299,300,320,321,388,401,456,674] (ssl_logger:_/_)
         dtls_gen_connection.beam:[377,439] (ssl_record:_/_)
         dtls_handshake.beam:124 (crypto:_/_)
         dtls_handshake.beam:[73,102,180] (dtls_record:_/_)
         dtls_handshake.beam:[76,184,215,229,261,271,274,346,347,373] (dtls_v1:_/_)
         dtls_handshake.beam:197 (ssl_cipher_format:_/_)
         dtls_handshake.beam:[77,79,87,113,179,185,187,189,198,214,227,260,270,274,348,349,356,374] (ssl_handshake:_/_)
         dtls_handshake.beam:329 (ssl_logger:_/_)
         dtls_handshake.beam:[74,89] (ssl_record:_/_)
         dtls_handshake.beam:101 (ssl_session:_/_)
         dtls_packet_demux.beam:279 (dtls_connection_sup:_/_)
         dtls_packet_demux.beam:359 (dtls_server_session_cache_sup:_/_)
         dtls_packet_demux.beam:[168,278] (dtls_socket:_/_)
         dtls_packet_demux.beam:360 (ssl_server_session_cache_sup:_/_)
         dtls_packet_demux.beam:343 (tls_socket:_/_)
         dtls_record.beam:636 (crypto:_/_)
         dtls_record.beam:[391,527,541,562,584,612] (dtls_v1:_/_)
         dtls_record.beam:543 (ssl_cipher:_/_)
         dtls_record.beam:[427,444] (ssl_logger:_/_)
         dtls_record.beam:[72,75,198,219,404,522,524,528,538,561,563,565,584,587,589] (ssl_record:_/_)
         dtls_record.beam:227 (tls_record:_/_)
         dtls_socket.beam:[54,64,100,312,316] (dtls_listener_sup:_/_)
         dtls_socket.beam:[58,59,74,101,122,138,157,176,280] (dtls_packet_demux:_/_)
         dtls_socket.beam:88 (ssl_gen_statem:_/_)
         dtls_socket.beam:[120,156,159,161,164,166] (tls_socket:_/_)
         dtls_v1.beam:59 (crypto:_/_)
         dtls_v1.beam:[41,47,78] (ssl_cipher:_/_)
         dtls_v1.beam:[34,39,45] (ssl_cipher_format:_/_)
         dtls_v1.beam:[36,50,53] (tls_v1:_/_)
         inet6_tls_dist.beam:[29,32,35,38,41,44,47,50] (inet_tls_dist:_/_)
         inet_tls_dist.beam:[355,442,466,485] (public_key:_/_)
         inet_tls_dist.beam:[130,133,144,150,167,178,184,250,262,274,437,439,540,547] (ssl:_/_)
         inet_tls_dist.beam:[187,415] (tls_sender:_/_)
         ssl.beam:1187 (crypto:_/_)
         ssl.beam:[776,1359] (dtls_packet_demux:_/_)
         ssl.beam:[1075,1094,1375,1386,1389,2486] (dtls_record:_/_)
         ssl.beam:[609,660,850,877,998,1002,1216,1275,1320,1329,1361,1579,2545] (dtls_socket:_/_)
         ssl.beam:[1383,1508,2487] (dtls_v1:_/_)
         ssl.beam:2394 (public_key:_/_)
         ssl.beam:[1117,1122,1561,1561,1564,1564,1569,1571,1573,2575,2576,2595,2597,2597] (ssl_cipher:_/_)
         ssl.beam:[1051,1054,1054,1058,1077,1096,1096,1099,1099,1523,1532,1548,2569,2572,2587,2591] (ssl_cipher_format:_/_)
         ssl.beam:[738,768,777,795,831,838,848,866,875,889,922,940,960,980,1016,1037,1214,1252,1256,1269,1345] (ssl_gen_statem:_/_)
         ssl.beam:1468 (ssl_pem_cache:_/_)
         ssl.beam:1439 (tls_connection_1_3:_/_)
         ssl.beam:[1410,1415,1456] (tls_dtls_connection:_/_)
         ssl.beam:[1072,1091,1374,1380,1383,1385,1388,1560,1563,2478,2487] (tls_record:_/_)
         ssl.beam:[891,1254,1408] (tls_sender:_/_)
         ssl.beam:[579,580,583,607,658,767,769,778,787,788,792,792,793,794,797,879,1000,1004,1227,1285,1323,1326,1357,1363,1576,2543] (tls_socket:_/_)
         ssl.beam:[1165,1183,1196,1203,1567,1845,2417,2427,2434,2440,2595,2622,2631] (tls_v1:_/_)
         ssl_app.beam:33 (ssl_sup:_/_)
         ssl_certificate.beam:[65,66,100,103,113,116,238,240,242,271,285,289,332,351,364,368,377,385,393,403,448,475,477,487,492,596] (public_key:_/_)
         ssl_certificate.beam:[426,427,430] (ssl_cipher:_/_)
         ssl_certificate.beam:[124,133,268,478,490] (ssl_manager:_/_)
         ssl_certificate.beam:[229,465] (ssl_pkix_db:_/_)
         ssl_cipher.beam:[168,172,176,180,184,186,190,193,258,261,278,282,286,288,611,707,1409,1411,1467,1477,1478,1488,1496,1497,1504,1505] (crypto:_/_)
         ssl_cipher.beam:[329,340,352] (dtls_v1:_/_)
         ssl_cipher.beam:[553,561,1005,1403,1405,1407,1413] (public_key:_/_)
         ssl_cipher.beam:[559,1359,1360,1371] (ssl_certificate:_/_)
         ssl_cipher.beam:[976,976,1440] (ssl_cipher:_/_)
         ssl_cipher.beam:[110,125,589] (ssl_cipher_format:_/_)
         ssl_cipher.beam:1413 (ssl_dh_groups:_/_)
         ssl_cipher.beam:[327,754] (tls_v1:_/_)
         ssl_config.beam:[118,128,133,138,143,144,161,171] (public_key:_/_)
         ssl_config.beam:[81,90] (ssl_certificate:_/_)
         ssl_config.beam:[165,165,173,173] (ssl_dh_groups:_/_)
         ssl_config.beam:[48,51,68,111,168] (ssl_manager:_/_)
         ssl_config.beam:[49,52] (ssl_pem_cache:_/_)
         ssl_crl.beam:[42,59,59,68,68,105,107] (public_key:_/_)
         ssl_crl.beam:[37,44,52] (ssl_certificate:_/_)
         ssl_crl.beam:[33,95] (ssl_pkix_db:_/_)
         ssl_crl_cache.beam:[81,94,151,159] (public_key:_/_)
         ssl_crl_cache.beam:[97,102,107,118] (ssl_manager:_/_)
         ssl_crl_cache.beam:[56,175] (ssl_pkix_db:_/_)
         ssl_crl_hash_dir.beam:[38,50,66,95] (public_key:_/_)
         ssl_dist_admin_sup.beam:66 (ssl_admin_sup:_/_)
         ssl_gen_statem.beam:1759 (pubkey_cert_records:_/_)
         ssl_gen_statem.beam:[518,782,1149,1156,1255] (ssl:_/_)
         ssl_gen_statem.beam:[1702,1705] (ssl_alert:_/_)
         ssl_gen_statem.beam:2009 (ssl_cipher:_/_)
         ssl_gen_statem.beam:[1754,1948] (ssl_cipher_format:_/_)
         ssl_gen_statem.beam:[161,1224] (ssl_config:_/_)
         ssl_gen_statem.beam:[471,649,782,1278] (ssl_handshake:_/_)
         ssl_gen_statem.beam:[483,484,816,846,1715,1721] (ssl_logger:_/_)
         ssl_gen_statem.beam:[1049,1735] (ssl_manager:_/_)
         ssl_gen_statem.beam:[1039,1047] (ssl_pkix_db:_/_)
         ssl_gen_statem.beam:[477,767,1780,1792] (ssl_record:_/_)
         ssl_gen_statem.beam:[462,463] (tls_handshake:_/_)
         ssl_gen_statem.beam:[460,461,474] (tls_handshake_1_3:_/_)
         ssl_gen_statem.beam:492 (tls_record:_/_)
         ssl_gen_statem.beam:601 (tls_sender:_/_)
         ssl_gen_statem.beam:482 (tls_socket:_/_)
         ssl_handshake.beam:[469,470,474,1060,1067,1078,1078,1079,1136,1767,1902,1907,1911,1914,3291,3307] (crypto:_/_)
         ssl_handshake.beam:[172,402,407,411,413,419,422,426,802,1053,1127,1129,1229,1245,1552,1613,1778,1918,1921,1924,1926,1929,2001,2012,2019,2022,2033,2045,2050,2076,3274,3467,3581] (public_key:_/_)
         ssl_handshake.beam:[140,148,357,1799,1817,1824,1829,1859] (ssl_certificate:_/_)
         ssl_handshake.beam:[577,577,666,666,674,682,872,872,981,981,985,1322,2111,2112,2148,2156,2296,2297,2520,2521,2527,2528,2533,2533,2538,2538,2626,2626,2640,2660,2850,2850,3092,3212,3238] (ssl_cipher:_/_)
         ssl_handshake.beam:[190,989,3464] (ssl_cipher_format:_/_)
         ssl_handshake.beam:1980 (ssl_crl:_/_)
         ssl_handshake.beam:3533 (ssl_logger:_/_)
         ssl_handshake.beam:1790 (ssl_pkix_db:_/_)
         ssl_handshake.beam:[110,439,449,516,1382,2106,2108,2114,2130,2132,2142,3369,3377,3387,3399,3404,3406,3410,3414,3430,3451] (ssl_record:_/_)
         ssl_handshake.beam:1029 (ssl_session:_/_)
         ssl_handshake.beam:1076 (ssl_srp_primes:_/_)
         ssl_handshake.beam:1317 (tls_client_ticket_store:_/_)
         ssl_handshake.beam:[641,648,733,1024,1046,1510,2086,2088,2118,2121,2208,2234,2357,2414,2451,2680,2699,2770,2780,2879] (tls_v1:_/_)
         ssl_logger.beam:[86,92,99] (ssl_alert:_/_)
         ssl_logger.beam:[264,266] (ssl_cipher_format:_/_)
         ssl_logger.beam:122 (tls_record:_/_)
         ssl_manager.beam:[90,102,131] (ssl_pem_cache:_/_)
         ssl_manager.beam:[114,125,129,147,225,280,285,313,318,343,368,441,443,444,445,536] (ssl_pkix_db:_/_)
         ssl_manager.beam:[390,398] (ssl_session:_/_)
         ssl_pem_cache.beam:[134,156,168,172,229] (ssl_pkix_db:_/_)
         ssl_pkix_db.beam:[152,165,305,308,355] (public_key:_/_)
         ssl_pkix_db.beam:[81,82,323] (ssl_pem_cache:_/_)
         ssl_record.beam:518 (crypto:_/_)
         ssl_record.beam:[355,367,408,427,439,469,501,508,513] (ssl_cipher:_/_)
         ssl_server_session_cache.beam:[80,123,223,224] (crypto:_/_)
         ssl_server_session_cache.beam:[145,178] (ssl_session:_/_)
         ssl_session.beam:46 (crypto:_/_)
         ssl_session.beam:[90,97,163] (ssl_server_session_cache:_/_)
         tls_connection.beam:[145,193,201,236,252,434,437,441,557,568] (ssl_gen_statem:_/_)
         tls_connection.beam:[164,173,175,485,592] (ssl_handshake:_/_)
         tls_connection.beam:[148,341] (ssl_session:_/_)
         tls_connection.beam:[258,274,277,286,295,304,313,398,422,505] (tls_dtls_connection:_/_)
         tls_connection.beam:[153,182,272,346,350,369,370,384,394,395,396,420,435,552,563] (tls_gen_connection:_/_)
         tls_connection.beam:[174,250,342,365,517] (tls_handshake:_/_)
         tls_connection.beam:[177,454] (tls_record:_/_)
         tls_connection.beam:[339,383] (tls_sender:_/_)
         tls_connection.beam:[178,408] (tls_socket:_/_)
         tls_connection_1_3.beam:243 (ssl:_/_)
         tls_connection_1_3.beam:171 (ssl_cipher_format:_/_)
         tls_connection_1_3.beam:[191,203,206,209,223,231,237,244,269,289,296,303,316,323,331,338,347,349,356,371,381,389,396,404,411,418,429,434,438,441] (ssl_gen_statem:_/_)
         tls_connection_1_3.beam:477 (ssl_handshake:_/_)
         tls_connection_1_3.beam:[506,517] (ssl_record:_/_)
         tls_connection_1_3.beam:485 (ssl_session:_/_)
         tls_connection_1_3.beam:521 (tls_client_ticket_store:_/_)
         tls_connection_1_3.beam:444 (tls_connection:_/_)
         tls_connection_1_3.beam:[192,204,257,294,299,308,311,318,321,326,333,336,342,350,354,360,376,379,385,391,394,400,406,413,416,422,427,430] (tls_gen_connection:_/_)
         tls_connection_1_3.beam:[156,267,287,301,314,329,345,369,387,402,409] (tls_handshake_1_3:_/_)
         tls_connection_1_3.beam:453 (tls_record:_/_)
         tls_connection_1_3.beam:157 (tls_sender:_/_)
         tls_connection_1_3.beam:[150,153] (tls_socket:_/_)
         tls_connection_1_3.beam:[168,172,509,520] (tls_v1:_/_)
         tls_dtls_connection.beam:[1413,1445,1494,1506,1519] (crypto:_/_)
         tls_dtls_connection.beam:[634,659] (dtls_connection:_/_)
         tls_dtls_connection.beam:1672 (dtls_v1:_/_)
         tls_dtls_connection.beam:[874,1040,1070,1112,1134,1423,1455,1679,1684] (public_key:_/_)
         tls_dtls_connection.beam:[174,198,219,380,383,391,433,491,507,530,562,592,715,744,834,902,1045,1075,1097,1117,1139,1163,1192,1206,1216,1230,1236,1244,1254,1266,1277,1290,1307,1334,1351,1394,1478,1631] (ssl:_/_)
         tls_dtls_connection.beam:[471,1642] (ssl_cipher:_/_)
         tls_dtls_connection.beam:[112,848,864] (ssl_cipher_format:_/_)
         tls_dtls_connection.beam:[82,85,95,159,168,175,205,210,229,233,259,295,315,329,356,398,415,435,454,476,497,515,524,534,539,571,579,601,623,638,642,647,668,675,684,722,725,826,843,924,1359,1533,1544,1638,1664] (ssl_gen_statem:_/_)
         tls_dtls_connection.beam:[198,219,349,380,390,432,452,473,491,507,530,565,592,715,744,834,853,875,887,901,945,965,970,976,985,993,1000,1006,1020,1045,1075,1097,1117,1139,1163,1192,1216,1230,1236,1244,1254,1277,1290,1307,1335,1337,1351,1381,1394,1415,1425,1446,1457,1468,1478,1631,1654] (ssl_handshake:_/_)
         tls_dtls_connection.beam:1595 (ssl_manager:_/_)
         tls_dtls_connection.beam:[203,224,250,617,700,1042,1072,1094,1114,1136,1160,1189,1333,1367,1402,1404,1406,1408,1531,1539,1559,1562] (ssl_record:_/_)
         tls_dtls_connection.beam:1598 (ssl_server_session_cache:_/_)
         tls_dtls_connection.beam:131 (ssl_session:_/_)
         tls_dtls_connection.beam:1518 (ssl_srp_primes:_/_)
         tls_dtls_connection.beam:[631,653] (tls_connection:_/_)
         tls_gen_connection.beam:749 (ssl_alert:_/_)
         tls_gen_connection.beam:[88,89,102,103,250,276,278,307,328,339,343,355,368,397,407,419,422,425,761,763] (ssl_gen_statem:_/_)
         tls_gen_connection.beam:[147,156,158,216,524] (ssl_handshake:_/_)
         tls_gen_connection.beam:[177,178,201,454] (ssl_logger:_/_)
         tls_gen_connection.beam:227 (ssl_record:_/_)
         tls_gen_connection.beam:[86,100] (tls_connection_sup:_/_)
         tls_gen_connection.beam:[157,385,523] (tls_handshake:_/_)
         tls_gen_connection.beam:[160,444,526,530,551,556,650,677,698] (tls_record:_/_)
         tls_gen_connection.beam:[85,99,135,208,468,471] (tls_sender:_/_)
         tls_gen_connection.beam:[161,191,234,237,240,453,479,501,635] (tls_socket:_/_)
         tls_handshake.beam:311 (crypto:_/_)
         tls_handshake.beam:311 (public_key:_/_)
         tls_handshake.beam:399 (ssl_cipher:_/_)
         tls_handshake.beam:348 (ssl_cipher_format:_/_)
         tls_handshake.beam:[85,86,93,244,256,330,336,338,340,349,370,385,426,435,463,464,470,477] (ssl_handshake:_/_)
         tls_handshake.beam:444 (ssl_logger:_/_)
         tls_handshake.beam:[84,97] (ssl_record:_/_)
         tls_handshake.beam:[177,200] (ssl_session:_/_)
         tls_handshake.beam:[433,475] (tls_handshake_1_3:_/_)
         tls_handshake.beam:[70,77,173,201,331,401,402] (tls_record:_/_)
         tls_handshake_1_3.beam:[134,135,1492,1636] (crypto:_/_)
         tls_handshake_1_3.beam:[1443,1641,1648,2253,2256,2608] (public_key:_/_)
         tls_handshake_1_3.beam:[249,1412] (ssl_certificate:_/_)
         tls_handshake_1_3.beam:[136,159,287,418,479,653,744,1491,1536,1543,1546,1548,1554,1565,1643,1786,1787,1943,2165,2198,2199,2220] (ssl_cipher:_/_)
         tls_handshake_1_3.beam:[1518,1611,2331,2497] (ssl_cipher_format:_/_)
         tls_handshake_1_3.beam:1640 (ssl_dh_groups:_/_)
         tls_handshake_1_3.beam:624 (ssl_gen_statem:_/_)
         tls_handshake_1_3.beam:[94,98,104,173,371,384,441,518,521,561,571,612,1053,1408,1421,2245,2338,2483,2588] (ssl_handshake:_/_)
         tls_handshake_1_3.beam:[775,776,1320] (ssl_logger:_/_)
         tls_handshake_1_3.beam:[73,283,314,657,802,821,890,921,970,976,1187,1297,1365,1397,1475,1485,1501,1593,1661,1916,1939,1961,1966] (ssl_record:_/_)
         tls_handshake_1_3.beam:[1564,1567,1570,1571,2485,2486,2510] (tls_client_ticket_store:_/_)
         tls_handshake_1_3.beam:[747,2379,2391,2422,2435,2436] (tls_handshake:_/_)
         tls_handshake_1_3.beam:765 (tls_handshake_1_3:_/_)
         tls_handshake_1_3.beam:1319 (tls_record:_/_)
         tls_handshake_1_3.beam:[1300,2332] (tls_server_session_ticket:_/_)
         tls_handshake_1_3.beam:774 (tls_socket:_/_)
         tls_handshake_1_3.beam:[292,317,1194,1504,1507,1513,1515,1519,1520,1523,1524,1599,1606,1608,1612,1613,1665,1950,2118,2450,2451,2452,2456] (tls_v1:_/_)
         tls_record.beam:[378,743] (crypto:_/_)
         tls_record.beam:[227,678] (ssl_cipher:_/_)
         tls_record.beam:581 (ssl_logger:_/_)
         tls_record.beam:[74,76,202,203,210,225,228,234,470,660,662,666,677,679] (ssl_record:_/_)
         tls_record.beam:[113,141,163,189] (tls_record_1_3:_/_)
         tls_record_1_3.beam:255 (crypto:_/_)
         tls_record_1_3.beam:[261,276] (ssl_cipher:_/_)
         tls_record_1_3.beam:[56,85] (tls_record:_/_)
         tls_sender.beam:281 (ssl_gen_statem:_/_)
         tls_sender.beam:[419,423,436,472,478,497,501,507] (ssl_logger:_/_)
         tls_sender.beam:516 (tls_connection_1_3:_/_)
         tls_sender.beam:457 (tls_dtls_connection:_/_)
         tls_sender.beam:275 (tls_gen_connection:_/_)
         tls_sender.beam:494 (tls_handshake:_/_)
         tls_sender.beam:[452,461] (tls_handshake_1_3:_/_)
         tls_sender.beam:[434,468,496] (tls_record:_/_)
         tls_sender.beam:[435,470,499] (tls_socket:_/_)
         tls_server_session_ticket.beam:[147,148,156,157,170,178,305] (crypto:_/_)
         tls_server_session_ticket.beam:[317,339] (ssl_cipher:_/_)
         tls_server_session_ticket.beam:[118,155,387,392] (tls_bloom_filter:_/_)
         tls_server_session_ticket.beam:205 (tls_handshake_1_3:_/_)
         tls_server_session_ticket.beam:[86,315] (tls_v1:_/_)
         tls_socket.beam:[111,125,140] (ssl_gen_statem:_/_)
         tls_socket.beam:[260,262] (ssl_listen_tracker_sup:_/_)
         tls_socket.beam:[281,281,283,283] (ssl_server_session_cache_sup:_/_)
         tls_socket.beam:109 (tls_connection_sup:_/_)
         tls_socket.beam:106 (tls_sender:_/_)
         tls_socket.beam:[270,273] (tls_server_session_ticket_sup:_/_)
         tls_socket.beam:[105,122] (tls_socket:_/_)
         tls_v1.beam:[99,144,171,172,186,196,197,203,577,628,732,796,838,878] (crypto:_/_)
         tls_v1.beam:841 (pubkey_cert_records:_/_)
         tls_v1.beam:[101,137,346,350,411,412,432,433,442,460,636] (ssl_cipher:_/_)
         tls_v1.beam:[423,424] (tls_v1:_/_)
         client_server.beam:[45,63] (public_key:_/_)
         client_server.beam:[33,34,41,42,44,47,48,50,52,60,62,64,67] (ssl:_/_)
         beam_lib.beam:[976,1012] (crypto:_/_)
         c.beam:[381,478,496,550] (compile:file/2)
         erl_abstract_code.beam:10 (compile:noenv_forms/2)
         escript.beam:[204,323,331,339,658] (compile:forms/2)
         qlc_pt.beam:444 (compile:noenv_forms/2)
         merl.beam:335 (compile:noenv_forms/2)
         cover.beam:1544 (compile:file/2)
         cover.beam:1605 (compile:forms/2)
         make.beam:272 (compile:file/2)
     10: Dynamic creation of atoms can exhaust atom memory
         asn1ct.beam:1897 (file:consult/1)
         ct_config_plain.beam:29 (file:consult/1)
         ct_config_xml.beam:48 (xmerl_sax_parser:_/_)
         ct_cover.beam:95 (file:consult/1)
         ct_logs.beam:[1142,1836] (file:consult/1)
         ct_make.beam:[90,146] (file:consult/1)
         ct_netconfc.beam:1366 (xmerl:_/_)
         ct_netconfc.beam:1435 (xmerl_sax_parser:_/_)
         ct_release_test.beam:[380,795] (file:consult/1)
         ct_run.beam:3216 (file:consult/1)
         ct_snmp.beam:[123,456,472,487,503,518,533,548,564] (file:consult/1)
         ct_testspec.beam:332 (file:consult/1)
         ct_util.beam:[231,1004,1009] (file:consult/1)
         test_server_ctrl.beam:[230,1270,5354] (file:consult/1)
         test_server_node.beam:161 (file:consult/1)
         test_server_sup.beam:[188,298,925] (file:consult/1)
         compile.beam:976 (file:consult/1)
         diameter_dbg.beam:146 (file:consult/1)
         edoc_data.beam:[116,513,524] (xmerl_lib:_/_)
         edoc_doclet.beam:[249,268,458] (xmerl:_/_)
         edoc_layout.beam:[99,1040,1065] (xmerl:_/_)
         edoc_wiki.beam:90 (xmerl_scan:_/_)
         docgen_edoc_xml_cb.beam:[42,48] (xmerl:_/_)
         docgen_otp_specs.beam:37 (xmerl:_/_)
         docgen_xmerl_xml_cb.beam:[53,56] (xmerl_lib:_/_)
         docgen_xml_to_chunk.beam:266 (xmerl_sax_parser:_/_)
         erlang.beam:423 (erlang:binary_to_atom/2)
         eunit_lib.beam:518 (file:path_consult/2)
         httpd.beam:61 (file:consult/1)
         httpd_sup.beam:142 (file:consult/1)
         inets.beam:240 (file:consult/1)
         hdlt.beam:41 (file:consult/1)
         erts_debug.beam:[437,468] (file:consult/1)
         inet_db.beam:282 (file:consult/1)
         net_adm.beam:50 (file:path_consult/2)
         megaco.beam:725 (file:consult/1)
         megaco_erl_dist_encoder.beam:[206,219,231,260,264,271,296] (erlang:binary_to_term/1)
         megaco_codec_transform.beam:95 (file:consult/1)
         observer_trace_wx.beam:1152 (file:consult/1)
         observer_wx.beam:507 (file:consult/1)
         reltool_server.beam:1433 (file:consult/1)
         dbg.beam:290 (file:consult/1)
         msacc.beam:94 (file:consult/1)
         system_information.beam:[529,693] (file:consult/1)
         release_handler.beam:[493,2071] (file:consult/1)
         release_handler.beam:526 (file:path_consult/2)
         systools_make.beam:[1824,1836] (file:consult/1)
         target_system.beam:39 (file:consult/1)
         snmp.beam:719 (file:consult/1)
         ssh_options.beam:918 (file:consult/1)
         make.beam:117 (file:consult/1)
         xref_parser.beam:283 (erlang:list_to_atom/1)
         sudoku_gui.beam:272 (file:consult/1)
         xmerl.beam:[163,169,180,183,206,209,265] (xmerl_lib:_/_)
         xmerl_eventp.beam:[163,174,209,218,242,251] (xmerl:_/_)
         xmerl_eventp.beam:[144,167,179,195,213,222,230,246,255,263,272,287,307,380,381,401,404,407] (xmerl_scan:_/_)
         xmerl_lib.beam:[470,472,474,476,479,481,483,485,488,490,492,494,498,500,502,504,507,509,511,513] (xmerl_ucs:_/_)
         xmerl_sax_parser.beam:[104,108] (xmerl_sax_parser_list:_/_)
         xmerl_scan.beam:[307,323,881,970,2466,2474,2483,2506,2513,2742,3000,3033,3073,3317,3425,3432,3752] (xmerl_lib:_/_)
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
(4772 total lines that represent an exhaustive search for possible problems):

    $ ./pest.erl -vb -d ~/installed/lib/erlang/lib/ -i
    [{90,"Port Drivers may cause undefined behavior",
      [{crashdump_viewer,debug,1},
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
       {dyntrace,on_load,0},
       {erl_init,start,2},
       {erl_tracer,on_load,0},
       {erlang,load_nif,2},
       {prim_buffer,on_load,0},
       {prim_file,on_load,0},
       {prim_net,on_load,0},
       {prim_net,on_load,1},
       {prim_socket,on_load,0},
       {prim_socket,on_load,1},
       {zlib,on_load,0}]},
     {80,"OS shell usage may require input validation",
      [{cpu_sup,get_uint32_measurement,2},
       {cpu_sup,handle_call,3},
       {cpu_sup,init,1},
       {cpu_sup,measurement_server_init,0},
       {cpu_sup,measurement_server_loop,1},
       {cpu_sup,measurement_server_restart,1},
       {cpu_sup,measurement_server_start,0},
    ...4671 more lines...                ]}]

For comparison, the default checks specified in the pest.erl source code
are below (81 lines that represent [all core problems](https://github.com/okeuday/pest/blob/master/src/pest.erl#L153-L215)):

    $ ./pest.erl -v -i
    [{90,"Port Drivers may cause undefined behavior",
      [{erl_ddll,load,2},
       {erl_ddll,load_driver,2},
       {erl_ddll,reload,2},
       {erl_ddll,reload_driver,2},
       {erl_ddll,try_load,3}]},
     {90,"NIFs may cause undefined behavior",[{erlang,load_nif,2}]},
     {80,"OS shell usage may require input validation",[{os,cmd,2}]},
     {80,"OS process creation may require input validation",
      [{erlang,open_port,2}]},
     {15,"Keep OpenSSL updated for crypto module use (run with \"-V crypto\")",
      ['OTP-PUB-KEY','PKCS-FRAME',crypto,crypto_ec_curves,dtls_connection,
       dtls_connection_sup,dtls_gen_connection,dtls_handshake,dtls_listener_sup,
       dtls_packet_demux,dtls_record,dtls_server_session_cache_sup,
       dtls_server_sup,dtls_socket,dtls_sup,dtls_v1,inet6_tls_dist,inet_tls_dist,
       pubkey_cert,pubkey_cert_records,pubkey_crl,pubkey_ocsp,pubkey_pbe,
       pubkey_pem,pubkey_ssh,public_key,snmp,snmp_app,snmp_app_sup,
       snmp_community_mib,snmp_conf,snmp_config,snmp_framework_mib,snmp_generic,
       snmp_generic_mnesia,snmp_index,snmp_log,snmp_mini_mib,snmp_misc,
       snmp_note_store,snmp_notification_mib,snmp_pdus,snmp_shadow_table,
       snmp_standard_mib,snmp_target_mib,snmp_user_based_sm_mib,snmp_usm,
       snmp_verbosity,snmp_view_based_acm_mib,snmpa,snmpa_acm,snmpa_agent,
       snmpa_agent_sup,snmpa_app,snmpa_authentication_service,snmpa_conf,
       snmpa_discovery_handler,snmpa_discovery_handler_default,snmpa_error,
       snmpa_error_io,snmpa_error_logger,snmpa_error_report,snmpa_get,
       snmpa_get_lib,snmpa_get_mechanism,snmpa_local_db,snmpa_mib,snmpa_mib_data,
       snmpa_mib_data_tttn,snmpa_mib_lib,snmpa_mib_storage,snmpa_mib_storage_dets,
       snmpa_mib_storage_ets,snmpa_mib_storage_mnesia,snmpa_misc_sup,snmpa_mpd,
       snmpa_net_if,snmpa_net_if_filter,snmpa_network_interface,
       snmpa_network_interface_filter,snmpa_notification_delivery_info_receiver,
       snmpa_notification_filter,snmpa_set,snmpa_set_lib,snmpa_set_mechanism,
       snmpa_supervisor,snmpa_svbl,snmpa_symbolic_store,snmpa_target_cache,
       snmpa_trap,snmpa_usm,snmpa_vacm,snmpc,snmpc_lib,snmpc_mib_gram,
       snmpc_mib_to_hrl,snmpc_misc,snmpc_tok,snmpm,snmpm_conf,snmpm_config,
       snmpm_misc_sup,snmpm_mpd,snmpm_net_if,snmpm_net_if_filter,snmpm_net_if_mt,
       snmpm_network_interface,snmpm_network_interface_filter,snmpm_server,
       snmpm_server_sup,snmpm_supervisor,snmpm_user,snmpm_user_default,
       snmpm_user_old,snmpm_usm,ssh,ssh_acceptor,ssh_acceptor_sup,ssh_agent,
       ssh_app,ssh_auth,ssh_bits,ssh_channel,ssh_channel_sup,ssh_cli,
       ssh_client_channel,ssh_client_key_api,ssh_connection,
       ssh_connection_handler,ssh_connection_sup,ssh_controller,
       ssh_daemon_channel,ssh_dbg,ssh_file,ssh_info,ssh_io,ssh_message,ssh_no_io,
       ssh_options,ssh_server_channel,ssh_server_key_api,ssh_sftp,ssh_sftpd,
       ssh_sftpd_file,ssh_sftpd_file_api,ssh_shell,ssh_subsystem_sup,ssh_sup,
       ssh_system_sup,ssh_tcpip_forward_acceptor,ssh_tcpip_forward_acceptor_sup,
       ssh_tcpip_forward_client,ssh_tcpip_forward_srv,ssh_transport,ssh_xfer,
       sshc_sup,sshd_sup,ssl,ssl_admin_sup,ssl_alert,ssl_app,ssl_certificate,
       ssl_cipher,ssl_cipher_format,ssl_config,ssl_connection_sup,ssl_crl,
       ssl_crl_cache,ssl_crl_cache_api,ssl_crl_hash_dir,ssl_dh_groups,
       ssl_dist_admin_sup,ssl_dist_connection_sup,ssl_dist_sup,ssl_gen_statem,
       ssl_handshake,ssl_listen_tracker_sup,ssl_logger,ssl_manager,ssl_pem_cache,
       ssl_pkix_db,ssl_record,ssl_server_session_cache,
       ssl_server_session_cache_db,ssl_server_session_cache_sup,ssl_session,
       ssl_session_cache,ssl_session_cache_api,ssl_srp_primes,ssl_sup,
       tls_bloom_filter,tls_client_ticket_store,tls_connection,tls_connection_1_3,
       tls_connection_sup,tls_dtls_connection,tls_gen_connection,tls_handshake,
       tls_handshake_1_3,tls_record,tls_record_1_3,tls_sender,
       tls_server_session_ticket,tls_server_session_ticket_sup,tls_server_sup,
       tls_socket,tls_sup,tls_v1,
       {compile,file,2},
       {compile,forms,2},
       {compile,noenv_file,2},
       {compile,noenv_forms,2}]},
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
       {file,eval,2},
       {file,path_consult,2},
       {file,path_eval,3},
       {file,path_script,3},
       {file,script,2}]}]

See [Usage](#usage) for more information.

Indirect Security Concerns in Elixir
------------------------------------

To provide a representation of security concerns related to Elixir
dependencies, the pest.erl script was ran on all of the Elixir 1.11.3
installation beam files with the result provided below:

    $ ./pest.erl -vb -D ErlangOTP/23.2.3 -p ~/installed/lib/elixir/lib/elixir/ebin ~/installed/lib/elixir/lib
     90: Port Drivers may cause undefined behavior
         Elixir.Mix.Tasks.Profile.Fprof.beam:194 (fprof:analyse/1)
         Elixir.Mix.Tasks.Profile.Fprof.beam:189 (fprof:apply/3)
         Elixir.Mix.Tasks.Profile.Fprof.beam:188 (fprof:profile/1)
     80: OS shell usage may require input validation
         Elixir.IEx.Introspection.beam:149 (os:cmd/1)
     80: OS process creation may require input validation
         Elixir.Code.Typespec.beam:158 (beam_lib:chunks/2)
         Elixir.Code.Typespec.beam:183 (beam_lib:info/1)
         Elixir.Code.beam:1400 (beam_lib:chunks/2)
         Elixir.Collectable.File.Stream.beam:42 (file:open/2)
         Elixir.Config.Provider.beam:332 (file:consult/1)
         Elixir.Enumerable.File.Stream.beam:78 (file:open/2)
         Elixir.Exception.beam:207 (beam_lib:chunks/2)
         Elixir.Exception.beam:[245,284] (erl_eval:expr/3)
         Elixir.File.beam:958 (file:copy/2)
         Elixir.File.beam:696 (file:copy/3)
         Elixir.File.beam:1384 (file:open/2)
         Elixir.File.beam:[1037,1048] (file:write_file/3)
         Elixir.GenEvent.beam:327 (gen:debug_options/2)
         Elixir.GenEvent.beam:355 (sys:handle_system_msg/7)
         Elixir.Module.ParallelChecker.beam:[323,123] (beam_lib:chunks/2)
         Elixir.Port.beam:207 (erlang:open_port/2)
         Elixir.Protocol.beam:502 (beam_lib:chunks/2)
         Elixir.Protocol.beam:557 (beam_lib:chunks/3)
         Elixir.Record.Extractor.beam:79 (epp:parse_file/2)
         Elixir.Record.Extractor.beam:114 (erl_eval:expr/2)
         Elixir.System.beam:830 (erlang:open_port/2)
         elixir.beam:280 (erl_eval:expr/5)
         elixir_compiler.beam:107 (beam_lib:chunks/2)
         elixir_erl.beam:26 (compile:noenv_forms/2)
         elixir_erl.beam:54 (erl_eval:expr/3)
         elixir_erl_compiler.beam:[39,54] (compile:noenv_forms/2)
         Elixir.IEx.CLI.beam:82 (erlang:open_port/2)
         Elixir.IEx.CLI.beam:63 (user:start/0)
         Elixir.IEx.Helpers.beam:1178 (compile:file/2)
         Elixir.IEx.Info.Atom.beam:52 (beam_lib:info/1)
         Elixir.IEx.Introspection.beam:181 (beam_lib:chunks/2)
         Elixir.IEx.Pry.beam:408 (beam_lib:chunks/2)
         Elixir.IEx.Pry.beam:438 (compile:noenv_forms/2)
         Elixir.Mix.Dep.Loader.beam:418 (file:consult/1)
         Elixir.Mix.Rebar.beam:50 (file:consult/1)
         Elixir.Mix.Rebar.beam:203 (file:script/2)
         Elixir.Mix.Release.beam:807 (beam_lib:chunks/3)
         Elixir.Mix.Release.beam:[323,541,416] (file:consult/1)
         Elixir.Mix.Release.beam:538 (systools:make_script/2)
         Elixir.Mix.Release.beam:550 (systools:script2boot/1)
         Elixir.Mix.Shell.beam:109 (erlang:open_port/2)
         Elixir.Mix.Tasks.Compile.App.beam:173 (file:consult/1)
         Elixir.Mix.Tasks.Compile.Erlang.beam:102 (compile:file/2)
         Elixir.Mix.Tasks.Compile.Erlang.beam:141 (epp:parse_file/3)
         Elixir.Mix.Tasks.Compile.Leex.beam:60 (leex:file/2)
         Elixir.Mix.Tasks.Compile.Yecc.beam:60 (yecc:file/2)
         Elixir.Mix.Tasks.Compile.beam:160 (file:consult/1)
         Elixir.Mix.Tasks.Profile.Fprof.beam:194 (fprof:analyse/1)
         Elixir.Mix.Tasks.Profile.Fprof.beam:189 (fprof:apply/3)
         Elixir.Mix.Tasks.Profile.Fprof.beam:188 (fprof:profile/1)
         Elixir.Mix.Tasks.Release.beam:1146 (erl_tar:create/3)
         Elixir.Mix.Tasks.Test.Coverage.beam:171 (cover:analyse/2)
         Elixir.Mix.Tasks.Test.Coverage.beam:187 (cover:analyse_to_file/3)
         Elixir.Mix.Tasks.Test.Coverage.beam:142 (cover:compile_beam_directory/1)
         Elixir.Mix.Tasks.Test.Coverage.beam:161 (cover:export/1)
         Elixir.Mix.Tasks.Test.Coverage.beam:91 (cover:import/1)
         Elixir.Mix.Tasks.Test.Coverage.beam:173 (cover:modules/0)
         Elixir.Mix.Tasks.Test.Coverage.beam:139 (cover:start/0)
         Elixir.Mix.Tasks.Test.Coverage.beam:138 (cover:stop/0)
         Elixir.Mix.Tasks.Xref.beam:252 (beam_lib:chunks/2)
     15: Keep OpenSSL updated for crypto module use (run with "-V crypto")
         Elixir.Code.Typespec.beam:158 (beam_lib:chunks/2)
         Elixir.Code.beam:1400 (beam_lib:chunks/2)
         Elixir.Exception.beam:207 (beam_lib:chunks/2)
         Elixir.Exception.beam:[245,284] (erl_eval:expr/3)
         Elixir.Module.ParallelChecker.beam:[323,123] (beam_lib:chunks/2)
         Elixir.Protocol.beam:502 (beam_lib:chunks/2)
         Elixir.Protocol.beam:557 (beam_lib:chunks/3)
         Elixir.Record.Extractor.beam:79 (epp:parse_file/2)
         Elixir.Record.Extractor.beam:114 (erl_eval:expr/2)
         elixir.beam:280 (erl_eval:expr/5)
         elixir_compiler.beam:107 (beam_lib:chunks/2)
         elixir_erl.beam:26 (compile:noenv_forms/2)
         elixir_erl.beam:54 (erl_eval:expr/3)
         elixir_erl_compiler.beam:[39,54] (compile:noenv_forms/2)
         Elixir.IEx.CLI.beam:63 (user:start/0)
         Elixir.IEx.Helpers.beam:1178 (compile:file/2)
         Elixir.IEx.Introspection.beam:181 (beam_lib:chunks/2)
         Elixir.IEx.Pry.beam:408 (beam_lib:chunks/2)
         Elixir.IEx.Pry.beam:438 (compile:noenv_forms/2)
         Elixir.Mix.Local.Installer.beam:369 (crypto:_/_)
         Elixir.Mix.PublicKey.beam:[38,39,56] (public_key:_/_)
         Elixir.Mix.Rebar.beam:203 (file:script/2)
         Elixir.Mix.Release.beam:807 (beam_lib:chunks/3)
         Elixir.Mix.Release.beam:499 (crypto:_/_)
         Elixir.Mix.Tasks.Compile.Erlang.beam:102 (compile:file/2)
         Elixir.Mix.Tasks.Compile.Erlang.beam:141 (epp:parse_file/3)
         Elixir.Mix.Tasks.Compile.Yecc.beam:60 (yecc:file/2)
         Elixir.Mix.Tasks.Test.Coverage.beam:171 (cover:analyse/2)
         Elixir.Mix.Tasks.Test.Coverage.beam:187 (cover:analyse_to_file/3)
         Elixir.Mix.Tasks.Test.Coverage.beam:142 (cover:compile_beam_directory/1)
         Elixir.Mix.Tasks.Test.Coverage.beam:161 (cover:export/1)
         Elixir.Mix.Tasks.Test.Coverage.beam:91 (cover:import/1)
         Elixir.Mix.Tasks.Test.Coverage.beam:173 (cover:modules/0)
         Elixir.Mix.Tasks.Test.Coverage.beam:139 (cover:start/0)
         Elixir.Mix.Tasks.Test.Coverage.beam:138 (cover:stop/0)
         Elixir.Mix.Tasks.Xref.beam:252 (beam_lib:chunks/2)
         Elixir.Mix.Utils.beam:574 (crypto:_/_)
     10: Dynamic creation of atoms can exhaust atom memory
         Elixir.EEx.Engine.beam:188 (erlang:binary_to_atom/2)
         Elixir.Code.Identifier.beam:205 (erlang:binary_to_atom/2)
         Elixir.Code.Typespec.beam:[399,402] (erlang:binary_to_atom/2)
         Elixir.Code.beam:1423 (erlang:binary_to_term/1)
         Elixir.Config.Provider.beam:332 (file:consult/1)
         Elixir.Kernel.CLI.beam:[416,427,436] (erlang:binary_to_atom/2)
         Elixir.Kernel.Utils.beam:261 (erlang:binary_to_atom/2)
         Elixir.Kernel.beam:[3889,4195,4199,5520] (erlang:binary_to_atom/2)
         Elixir.List.beam:792 (erlang:list_to_atom/1)
         Elixir.Macro.beam:386 (erlang:binary_to_atom/2)
         Elixir.Module.ParallelChecker.beam:324 (erlang:binary_to_term/1)
         Elixir.Module.beam:[890,923,857,846] (erlang:binary_to_atom/2)
         Elixir.Module.beam:1156 (erlang:list_to_atom/1)
         Elixir.OptionParser.beam:779 (erlang:binary_to_atom/2)
         Elixir.Protocol.beam:272 (erlang:binary_to_atom/2)
         Elixir.Record.Extractor.beam:39 (erlang:list_to_atom/1)
         Elixir.String.beam:2329 (erlang:binary_to_atom/2)
         Elixir.ExUnit.Assertions.beam:328 (erlang:binary_to_atom/2)
         Elixir.ExUnit.Callbacks.beam:562 (erlang:binary_to_atom/2)
         Elixir.ExUnit.Case.beam:[548,552] (erlang:binary_to_atom/2)
         Elixir.ExUnit.FailuresManifest.beam:58 (erlang:binary_to_term/1)
         Elixir.ExUnit.Filters.beam:[124,125] (erlang:binary_to_atom/2)
         Elixir.IEx.Autocomplete.beam:371 (erlang:binary_to_atom/2)
         Elixir.IEx.CLI.beam:163 (erlang:list_to_atom/1)
         Elixir.IEx.Helpers.beam:133 (erlang:binary_to_atom/2)
         Elixir.IEx.Introspection.beam:594 (erlang:binary_to_atom/2)
         Elixir.IEx.Pry.beam:486 (erlang:binary_to_atom/2)
         Elixir.Logger.Formatter.beam:96 (erlang:binary_to_atom/2)
         Elixir.Mix.CLI.beam:113 (erlang:binary_to_atom/2)
         Elixir.Mix.Compilers.Elixir.beam:559 (erlang:binary_to_atom/2)
         Elixir.Mix.Compilers.Elixir.beam:[654,154] (erlang:binary_to_term/1)
         Elixir.Mix.Compilers.Erlang.beam:215 (erlang:binary_to_term/1)
         Elixir.Mix.Compilers.Test.beam:164 (erlang:binary_to_term/1)
         Elixir.Mix.Dep.Converger.beam:[310,314] (erlang:binary_to_atom/2)
         Elixir.Mix.Dep.ElixirSCM.beam:26 (erlang:binary_to_term/1)
         Elixir.Mix.Dep.Fetcher.beam:149 (erlang:binary_to_atom/2)
         Elixir.Mix.Dep.Loader.beam:418 (file:consult/1)
         Elixir.Mix.Dep.beam:576 (erlang:binary_to_atom/2)
         Elixir.Mix.Local.Installer.beam:[257,226,230] (erlang:binary_to_atom/2)
         Elixir.Mix.Rebar.beam:50 (file:consult/1)
         Elixir.Mix.Rebar.beam:203 (file:script/2)
         Elixir.Mix.Release.beam:[323,541,416] (file:consult/1)
         Elixir.Mix.State.beam:[15,16] (erlang:binary_to_atom/2)
         Elixir.Mix.Task.beam:[272,355,141] (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.App.Tree.beam:50 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Compile.App.beam:215 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Compile.App.beam:173 (file:consult/1)
         Elixir.Mix.Tasks.Compile.Erlang.beam:[96,223] (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Compile.Protocols.beam:177 (erlang:binary_to_term/1)
         Elixir.Mix.Tasks.Compile.beam:206 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Compile.beam:160 (file:consult/1)
         Elixir.Mix.Tasks.Deps.Clean.beam:42 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Deps.Get.beam:29 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Deps.Tree.beam:[45,56] (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Deps.Update.beam:[51,71] (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Escript.Build.beam:174 (erlang:binary_to_atom/2)
         Elixir.Mix.Tasks.Format.beam:226 (erlang:binary_to_term/1)
         Elixir.Mix.Tasks.Release.beam:1021 (erlang:binary_to_atom/2)

To cache all indirect security concerns for Elixir 1.11.3 using
Erlang/OTP 23.2.3 the following command line was used:

    ./pest.erl -vb -p ~/installed/lib/elixir/lib/elixir/ebin -d ~/installed/lib/elixir/lib -U pest/dependency/Elixir/1.11.3/23.2.3

To search an Elixir project's beam files for any indirect security concerns
related to the Elixir 1.11.3 source code and the Erlang/OTP 23.2.3 source code,
the command line arguments `-D ErlangOTP/23.2.3 -D Elixir/1.11.3/23.2.3` may be
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

    ./pest.erl -vb -d ~/installed/lib/erlang/lib/ -U pest/dependency/ErlangOTP/22.3.4.1
    ./pest.erl -vb -d ~/installed/lib/erlang/lib/ -U pest/dependency/ErlangOTP/23.2.3
    ./pest.erl -vb -p ~/installed/lib/elixir/lib/elixir/ebin -d ~/installed/lib/elixir/lib -U pest/dependency/Elixir/1.11.3/23.2.3
    ./pest.erl -U crypto

Author
------

Michael Truog (mjtruog at protonmail dot com)

License
-------

MIT License

