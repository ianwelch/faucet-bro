##! Detect file downloads that have hash values matching files in Team
##! Cymru's Malware Hash Registry (http://www.team-cymru.org/Services/MHR/).

@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

export {

	## File types to attempt matching against the Malware Hash Registry.
	const match_file_types = /application\/x-dosexec/ |
	                         /application\/vnd.ms-cab-compressed/ |
	                         /application\/pdf/ |
	                         /application\/x-shockwave-flash/ |
	                         /application\/x-java-applet/ |
	                         /application\/jar/ |
	                         /video\/mp4/ &redef;

	const notice_threshold = 10 &redef;
}

function do_mhr_lookup(hash: string): bool
	{
	local hash_domain = fmt("%s.malware.hash.cymru.com", hash);
    
	when ( local MHR_result = lookup_hostname_txt(hash_domain) )
		{
		# Data is returned as "<dateFirstDetected> <detectionRate>"
		local MHR_answer = split_string1(MHR_result, / /);
        
		if ( |MHR_answer| == 2 )
			{
			local mhr_detect_rate = to_count(MHR_answer[1]);
            
			if ( mhr_detect_rate >= notice_threshold )
				{
				return T;
				}
			}
		}
		return F;
	}

event file_hash(f: fa_file, kind: string, hash: string){
    
	if ( kind == "sha1" && f?$info && f$info?$mime_type && 
         match_file_types in f$info$mime_type ){
        if (do_mhr_lookup(hash)){
            for (c in f$conns) {
                piped_exec("python block_port.py", f$conns[c]$orig$l2_addr);
                print "Quarantined MAC:", f$conns[c]$orig$l2_addr;
                break;
            }
        }
    }
}
