//pacfile for 164.138.160.107 from 2_12039
function FindProxyForURL(url, host)
{
    /* Convert the host parameter to lowercase
       to facilitate case insensitive matching.
    */
    host = host.toLowerCase();


    /* Use specified alternative proxy */
    /* List format is: "<domain1>,<altproxy1>", "<domain2>,<altproxy2>",... */
    var domain_list = new Array("www.census.gov,cluster.n.webdefence.global.blackspider.com:8081,", "www.bwf.org.uk,webdefence.cluster-a.blackspider.com,", "veolia.myprintdesk.net,webdefence.cluster-r.blackspider.com,", "dca.gov.my,cluster.c.webdefence.global.blackspider.com");
    for (d in domain_list)
    {
        split_d = domain_list[d].split(",");
        if ( dnsDomainIs(host, "." + split_d[0] ) || host == split_d[0])
        {
            return 'PROXY ' + split_d[1];
        }
    }

    /* Don't proxy local hostnames */
    if (isPlainHostName(host))
    {
        return 'DIRECT';
    }

    /* always proxy on normal service address/port for the login host */
    if (shExpMatch(host, '*proxy-login.blackspider.com'))
    {
        return 'PROXY webdefence.global.blackspider.com:8081';
    }

    /* Don't proxy local domains */
    var domain_list = new Array("eus2-roaming.officeapps.live.com",
"eus-odc.officeapps.live.com",
"excel.officeapps.live.com",
"feedback.skype.com",
"firstpartyapps.oaspapps.com",
"giphy.com",
"groupsapi2-prod.outlookgroups.ms",
"groupsapi3-prod.outlookgroups.ms",
"groupsapi4-prod.outlookgroups.ms",
"groupsapi-prod.outlookgroups.ms",
"hackerrank.com");
    for (d in domain_list)
    {
        if ( dnsDomainIs(host, "." + domain_list[d] ) || host == domain_list[d] )
        {
            return 'DIRECT';
        }
    }

    /* Don't proxy portal addresses */
    if ((host == 'www.blackspider.com') ||
dnsDomainIs(host, '.mailcontrol.com') ||
(host == 'home.webdefence.global.blackspider.com') ||
(host == 'home.webdefence.global.forcepoint.net') ||
(host == 'webdefence.global.blackspider.com') ||
(host == 'webdefence.global.forcepoint.net') ||
(host == 'hybrid-web.global.blackspider.com') ||
(host == 'hybrid-web.global.forcepoint.net') ||
(host == 'pac.webdefence.global.blackspider.com') ||
(host == 'pac.webdefence.global.forcepoint.net') ||
(host == 'pac.hybrid-web.global.blackspider.com') ||
(host == 'pac.hybrid-web.global.forcepoint.net') ||
(host == 'download.global.blackspider.com') ||
(host == 'download.global.forcepoint.net') ||
(host == 'mobile.websense.net') ||
(host == 'mdm.websense.net') ||
(host == 'admin.websense.net') ||
(host == 'admin.forcepoint.net') ||
(host == 'status.websense.net') ||
(host == 'epevents.blackspider.com'))
    {
        return 'DIRECT';
    }

    /* Don't proxy Windows Update */
    if ((host == "download.microsoft.com") ||
(host == "ntservicepack.microsoft.com") ||
(host == "cdm.microsoft.com") ||
(host == "download.windowsupdate.com") ||
(host == "officecdn.microsoft.com.edgesuite.net") ||
(host == "wustat.windows.com") ||
(host == "windowsupdate.microsoft.com") ||
(dnsDomainIs(host, ".windowsupdate.microsoft.com")) ||
(host == "update.microsoft.com") ||
(dnsDomainIs(host, ".update.microsoft.com")) ||
(dnsDomainIs(host, ".windowsupdate.com") && host != "ctldl.windowsupdate.com") ||(dnsDomainIs(host, ".v4.download.windowsupdate.com")) ||
(host == "officecdn.microsoft.com") ||
(host == "sci2-1.am.microsoft.com") ||
(dnsDomainIs(host, ".mp.microsoft.com")) ||
(dnsDomainIs(host, ".dl.ws.microsoft.com")) ||
(dnsDomainIs(host, ".delivery.mp.microsoft.com")) ||
(host == "query1.finance.yahoo.com") ||
(host == "query2.finance.yahoo.com"))
    {
        return 'DIRECT';
    }

    /* Don't proxy Office 365 */
    var domain_pattern_list = new Array();
    for (d in domain_pattern_list)
    {
        if (shExpMatch(host, domain_pattern_list[d]))
        {
            return 'DIRECT';
        }
    }

    /* Don't proxy redirects to SSO gateway */
    if (false)
    {
        return 'DIRECT';
    }

    /* Handle SSO redirector requests for roaming users */
    if (false)
    {
        return 'DIRECT';
    }

    /* Query page should always resolve to the proxy - even if it's treated as a local address */
    if (isResolvable(host) & !(shExpMatch(url, 'http://query.webdefence.global.blackspider.com/*')))
    {
        var hostIP = dnsResolve(host);

        /* Use specified alternative proxy */
        /* List format is:  "<ip1>,<mask1>,<altproxy1>", "<ip2>,<mask2>,<altproxy2>",... */
        var address_list = new Array();
        for (a in address_list)
        {
            split_a = address_list[a].split(",");
            if (isInNet(hostIP, split_a[0], split_a[1]))
            {
                return 'PROXY ' + split_a[2];
            }
        }

        /* Don't proxy non-routable addresses (RFC 3330) */
        if (isInNet(hostIP, '0.0.0.0', '255.0.0.0') ||
isInNet(hostIP, '10.0.0.0', '255.0.0.0') ||
isInNet(hostIP, '127.0.0.0', '255.0.0.0') ||
isInNet(hostIP, '169.254.0.0', '255.255.0.0') ||
isInNet(hostIP, '172.16.0.0', '255.240.0.0') ||
isInNet(hostIP, '192.0.2.0', '255.255.255.0') ||
isInNet(hostIP, '192.88.99.0', '255.255.255.0') ||
isInNet(hostIP, '192.168.0.0', '255.255.0.0') ||
isInNet(hostIP, '198.18.0.0', '255.254.0.0') ||
isInNet(hostIP, '224.0.0.0', '240.0.0.0') ||
isInNet(hostIP, '240.0.0.0', '240.0.0.0') ||
isInNet(hostIP, '100.64.0.0', '255.192.0.0'))
        {
            return 'DIRECT';
        }

        /* Don't proxy local addresses */
        if (false)
        {
            return 'DIRECT';
        }
    }

    if (url.substring(0, 6) == 'https:' || url.substring(0, 4) == 'wss:')
    {
        var pats = new Array("");
        for (i in pats)
        {
            if (shExpMatch(host, pats[i].toLowerCase()))
            {
                // non-SSL-terminate hosts must use the normal address/port
                return 'PROXY webdefence.global.blackspider.com:8081';
            }
        }
    }
    if (url.substring(0, 5) == 'http:' || url.substring(0, 6) == 'https:' || url.substring(0, 4) == 'wss:')
    {
        return 'PROXY webdefence.global.blackspider.com:8081';
    }
    if (url.substring(0, 4) == 'ftp:')
    {
        // ftp must use the normal address/port
        return 'PROXY webdefence.global.blackspider.com:8081';
    }
    return 'DIRECT';
}
