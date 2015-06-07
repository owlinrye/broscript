@load frameworks/communication/listen

#author wangmb@ctrip.com

global ext_map: table[string] of string = {
        ["application/x-dosexec"] = "exe",
        ["application/msword"] = "doc",
        ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
        ["application/rtf"] = "rtf",
        ["application/vnd.ms-excel"] = "xls",
        ["application/x-excel"] = "xls",
        ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
        ["application/vnd.ms-powerpoint"] = "ppt",
        ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = "pptx",
        ["application/vnd.openxmlformats-officedocument.presentationml.slideshow"] = "ppsx",
        ["application/pdf"] = "pdf",
        ["application/x-shockwave-flash"] = "swf",
        ["application/x-msdownload"] = "dll",
        ["application/octet-stream"] = "exe",
        ["application/x-rar-compressed"] = "rar",
        ["application/zip"] = "zip"
} &default = "";


redef Communication::nodes += {
        ["extract_file"] = [$host =127.0.0.1, $connect=F, $ssl=F]
};

function SetAddr2str(S: set[addr]):string
{
	local str = "[";
	local i = 0;
	for(item in S ){
		local item_str = fmt("\"%s\"",item);
		if(i==0) str += item_str;
		else   str += ","+ item_str;
		i += 1;
	}
	return str += "]";
}

function SetStr2str(S: set[string]):string
{
	local str = "[";
	local i = 0;
	for(item in S ){
		local item_str = fmt("\"%s\"",item);
		if(i==0) str += item_str;
		else   str += ","+ item_str;
		i += 1;
	}
	return	str += "]";
}

type file_info:	record{
	ts: time;
	fuid: string; 
	tx_hosts: string;
	rx_hosts: string;
	conn_uids: string;	
	depth: count;
	analyzers: string;
	mime_type: string;
	filename: string;
	is_orig: bool;
	local_orig: bool;
	total_bytes: count;
	extracted: string;
	md5: string;
	sha1: string;
};

global	extract_file: event(info: file_info);

redef FileExtract::prefix = "/opt/filehouse/";
redef FileExtract::default_limit = 20000000;


event file_new(f: fa_file)
{
        local ext = "";
        if(f?$mime_type)
                ext = ext_map[f$mime_type];

        if(ext!="")
        {
                local fname = fmt("%s-%s.%s",f$source,f$id,ext);
		Files::add_analyzer(f, Files::ANALYZER_MD5);
		Files::add_analyzer(f, Files::ANALYZER_SHA1);
                Files::add_analyzer(f,Files::ANALYZER_EXTRACT,[$extract_limit=20000000,$extract_filename=fname]);

        }
}

event file_state_remove(f: fa_file) &priority=9
{

	if(f$info?$extracted)
	{
		# create extract file event
                local   finfo: file_info;
                finfo$ts = f$info$ts;
                finfo$fuid = f$id;
                finfo$tx_hosts = SetAddr2str(f$info$tx_hosts);
                finfo$rx_hosts = SetAddr2str(f$info$rx_hosts);
                finfo$conn_uids = SetStr2str(f$info$conn_uids);
                finfo$depth = f$info$depth;
                finfo$analyzers =  SetStr2str(f$info$analyzers);
                finfo$mime_type = (f$info?$mime_type)? f$info$mime_type : "";
                finfo$filename = (f$info?$filename)? f$info$filename : "";
                finfo$is_orig = (f$info?$is_orig)? f$info$is_orig : F;
                finfo$local_orig = (f$info?$local_orig)? f$info$local_orig : F;
                finfo$total_bytes = f$info$total_bytes;
                finfo$extracted = f$info$extracted;
		finfo$md5 = (f$info?$md5)? f$info$md5 : "";
		finfo$sha1 = (f$info?$sha1)? f$info$sha1 : "";
		
		event extract_file(finfo);
	}

}
