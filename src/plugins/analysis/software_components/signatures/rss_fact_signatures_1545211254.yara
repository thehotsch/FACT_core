rule curl_all_all {
	meta:
		software_name = "curl"
		open_source = "TODO"
		website = "TODO"
		description = "TODO"
		min_version = "7.13.2"
		max_version = "7.51.0"
		version_regex = "\\d\\.\\d\\d\\.\\d"

	strings:
		$s = "If this HTTPS server uses a certificate signed by a CA represented in\n the bundle, the certificate verification probably failed due to a\n problem with the certificate (it might be expired, or the name might\n not match the domain name in the URL).\nIf you'd like to turn off curl's verification of the certificate, use\n the -k (or --insecure) option.\n\x00"
		$vr = /curl (\d\.\d\d\.\d) \([\-\d_a-z]*-linux-[\da-z]*\) %s\n\x00/

	condition:
		$s and $vr and no_text_file
}

rule busybox_busybox__0_60_0__1_22_1 {
	meta:
		software_name = "busybox"
		open_source = "TODO"
		website = "TODO"
		description = "TODO"
		min_version = "0.60.0"
		max_version = "1.22.1"
		version_regex = "\\d\\.\\d[\\d\\-a-z]*\\.?[\\da-z]*"

	strings:
		$s = "busybox\x00"
		$vr = /[\n\r.@A-Z\d|]*BusyBox v(\d\.\d[\d\-a-z]*\.?[\da-z]*) \([\x00 )+.:<>A-Z\-\da-z]*/

	condition:
		$s and $vr and no_text_file
}

rule busybox_busybox__1_24_2 {
	meta:
		software_name = "busybox"
		open_source = "TODO"
		website = "TODO"
		description = "TODO"
		min_version = "1.24.2"
		max_version = "1.24.2"
		version_regex = "\\d\\.\\d\\d\\.\\d"

	strings:
		$s = "BusyBox is copyrighted by many authors between 1998-2015.\nLicensed under GPLv2. See source distribution for detailed\ncopyright notices.\n\nUsage: busybox [function [arguments]...]\n   or: busybox --list\n   or: function [arguments]...\n\n\tBusyBox is a multi-call binary that combines many common Unix\n\tutilities into a single executable.  Most people will create a\n\tlink to busybox for each function they wish to use and BusyBox\n\twill act like whatever it was invoked as.\n\nCurrently defined functions:\n\x00"
		$vr = /crond \(busybox (\d\.\d\d\.\d)\) started, log level %d\x00/

	condition:
		$s and $vr and no_text_file
}

rule dropbear_all_all {
	meta:
		software_name = "dropbear"
		open_source = "TODO"
		website = "TODO"
		description = "TODO"
		min_version = "0.48"
		max_version = "2015.67"
		version_regex = "[\\d]+\\.\\d\\d\\.?\\d?"

	strings:
		$s = "/etc/dropbear/dropbear_dss_host_key\x00"
		$vr = /SSH-2\.0-dropbear_([\d]+\.\d\d\.?\d?)\r\n\x00/

	condition:
		$s and $vr and no_text_file
}

rule samba_all_all {
	meta:
		software_name = "samba"
		open_source = "TODO"
		website = "TODO"
		description = "TODO"
		min_version = "3.0.24"
		max_version = "3.5.15"
		version_regex = "\\d\\.\\d\\.[\\d]+"

	strings:
		$s = "Failed to register vfs module.\nThe module was compiled against SMB_VFS_INTERFACE_VERSION %d,\ncurrent SMB_VFS_INTERFACE_VERSION is %d.\nPlease recompile against the current Samba Version!\n\x00"
		$vr = /[+.<>A-Z\-\/\d_a-z]*samba[\/a-z]*-(\d\.\d\.[\d]+)[_a-z]*\/source[\d]*\x00/

	condition:
		$s and $vr and no_text_file
}

rule lighttpd_all_all {
	meta:
		software_name = "lighttpd"
		open_source = "TODO"
		website = "TODO"
		description = "TODO"
		min_version = "1.4.18"
		max_version = "1.4.39"
		version_regex = "\\d\\.\\d\\.\\d\\d"

	strings:
		$s = "plugin-version doesn't match lighttpd-version for\x00"
		$vr = /\r\nServer: lighttpd\/(\d\.\d\.\d\d)[A-Z\-\da-z]*\x00/

	condition:
		$s and $vr and no_text_file
}

rule wget_all_all {
	meta:
		software_name = "wget"
		open_source = "TODO"
		website = "TODO"
		description = "TODO"
		min_version = "1.10"
		max_version = "1.16"
		version_regex = "\\d\\.\\d\\d\\.?\\d?"

	strings:
		$s = "Mail bug reports and suggestions to <bug-wget@gnu.org>.\n\x00"
		$vr = /(\d\.\d\d\.?\d?)\x00/

	condition:
		$s and $vr and no_text_file
}

rule openssl_all_all {
	meta:
		software_name = "openssl"
		open_source = "TODO"
		website = "TODO"
		description = "TODO"
		min_version = "0.9.8e"
		max_version = "1.1.0b"
		version_regex = "\\d\\.\\d\\.\\d[a-z]*"

	strings:
		$s = "OpenSSL application user interface\x00"
		$vr = /OpenSSL (\d\.\d\.\d[a-z]*)[ A-Z\-\da-z]*20[\d]*\x00/

	condition:
		$s and $vr and no_text_file
}
