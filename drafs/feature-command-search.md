# feature command search

----

datetime: Wed Jul  7 01:19:43 CST 2021   
author: Euruson

----

## search Implementation in msf
service start 
```ruby
#Metasploit::Framework::Command::Console#start
    def start
    case parsed_options.options.subcommand
    when :version
      $stderr.puts "Framework Version: #{Metasploit::Framework::VERSION}"
    else
      spinner unless parsed_options.options.console.quiet
      driver.run
    end
```

while loop Waiting for command  
This layer handles exiting or continuing to execute commands
```ruby
#Rex::Ui::Text::Shell#run
          run_single(line)
```

This layer parses parameters , handles exception  and uses dispatcher to call the real command execution function (ruby send)
```ruby
#Rex::Ui::Text::DispatcherShell#run_command
            run_command(dispatcher, method, arguments)
```

This layer dispatcher to call the real command execution function (ruby send)
```ruby
#Rex::Ui::Text::DispatcherShell#run_command
      dispatcher.send('cmd_' + method, *arguments)
```

command `search` 
```ruby
#Msf::Ui::Console::CommandDispatcher::Modules#cmd_search
          def cmd_search(*args)
            # print command `search` help info  if without any options
            # match           <= parse(['-S','-h','-o','-u','-I','-s','-r']) 
            # search_params   <= parse_search_string(match) -> Hash
            # serach_results  <= find(search_params) 
            # sort if '-s';desc if '-r'; and ...
            # make table for print format;style;color; ...
            
```

load from cache
```ruby
#Msf::Modules::Metadata::Search#find
    get_metadata.each { |module_metadata|
```

if cache return else load
```
#Msf::Modules::Metadata::Cache#get_metadata
  #
  #  Returns the module data cache, but first ensures all the metadata is loaded
  #
  def get_metadata
    @mutex.synchronize {
      wait_for_load
      @module_metadata_cache.values
    }
  end
```

load metadata
```pseudocode
load 
if 
 user store 
else 
 load from base 
 cp to user store
```
`initialize`->`init_store`->`load_metadata`->`load_cache_from_file_store`-> load from [user json file | db ]


```ruby
#Msf::Modules::Metadata::Store
  BaseMetaDataFile = 'modules_metadata_base.json'
  UserMetaDataFile = 'modules_metadata.json'
```

data schema
```ruby
 "auxiliary_admin/backupexec/dump": {
    "name": "Veritas Backup Exec Windows Remote File Access",
    "fullname": "auxiliary/admin/backupexec/dump",
    "aliases": [

    ],
    "rank": 300,
    "disclosure_date": null,
    "type": "auxiliary",
    "author": [
      "hdm <x@hdm.io>",
      "Unknown"
    ],
    "description": "This module abuses a logic flaw in the Backup Exec Windows Agent to download\n        arbitrary files from the system. This flaw was found by someone who wishes to\n        remain anonymous and affects all known versions of the Backup Exec Windows Agent. The\n        output file is in 'MTF' format, which can be extracted by the 'NTKBUp' program\n        listed in the references section. To transfer an entire directory, specify a\n        path that includes a trailing backslash.",
    "references": [
      "CVE-2005-2611",
      "OSVDB-18695",
      "BID-14551",
      "URL-http://www.fpns.net/willy/msbksrc.lzh"
    ],
    "platform": "",
    "arch": "",
    "rport": 10000,
    "autofilter_ports": [

    ],
    "autofilter_services": [

    ],
    "targets": null,
    "mod_time": "2021-02-26 10:13:11 +0000",
    "path": "/modules/auxiliary/admin/backupexec/dump.rb",
    "is_install_path": true,
    "ref_name": "admin/backupexec/dump",
    "check": false,
    "post_auth": false,
    "default_credential": false,
    "notes": {
    },
    "session_types": false,
    "needs_cleanup": false
  },
```


`cmd_reload_all`
Take the command `cmd_reload_all` as a clue, how the module is loaded
```ruby
#Msf::Ui::Console::CommandDispatcher::Modules#cmd_reload_all
            framework.modules.reload_modules
```

```ruby
#module Msf::ModuleManager::Reloading
#Msf::ModuleManager::Loading#load_modules -> Msf::Modules::Loader::Base#load_module ->Msf::Modules::Loader::Base#read_module_content
```

Module Scheme
```ruby
class MetasploitModule < Msf::Exploit::Remote
# init update info Module info schema Msf::Module::ModuleInfo
```

## conclusion
Search implementation draft
- Design a info schema
- Refactoring Phinx Module Base Class record module info, Instead of using string records in the code
- Add reload/load: load module info from module into metainfo 
- Add find: search module info from metainfo or cache load from metainfo.
