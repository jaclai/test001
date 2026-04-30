//=================================================================test001-002
/* https://pac.zscloud.net/1P7tpJWL3FZl/lvmh-zcc-T2-app.pac */
//=================================================================

function FindProxyForURL(url, host)
{
    
	/********************************/
	/*								*/
	/* 		Variable definitions 	*/
	/*								*/
	/********************************/

	


	var proxy_on  = "PROXY 58.220.95.15:9400; PROXY 221.122.91.36:9400; DIRECT" ; // Zscaler Geoloc using LVMH Subcloud.
	var proxy_china = "PROXY 140.210.152.47:9400; PROXY 220.243.154.47:9400; DIRECT" ; //China Zscaler Public Nodes in LVMH Subcloud China.
	var country = "China";
	var public_ip = "103.204.73.234";
	var customPort = "9400";
	var User_Lan_IP = myIpAddress();
	var privateIP =/^(0|10|127|192\.168|172\.1[6789]|172\.2[0-9]|172\.3[01]|169\.254|192\.88\.99)\.[0-9.]+$/;
	
	var InternalNetwork = "FALSE";
	if ( dnsResolve("zscalerkeepalive.group.lvmh.com") == "10.106.22.10"		
	) 
	InternalNetwork = "TRUE";
	
	var P66Network = "FALSE";
	if (
		isInNet(public_ip, "119.18.234.32", "255.255.255.224") ||							// Users in P66 with Hogan Public IP
		isInNet(public_ip, "180.167.31.222", "255.255.255.255") ||	        				// LoroPiana in P66 with Local Internet Loop
		isInNet(public_ip, "180.169.163.14", "255.255.255.255") ||	        				// Berluti in P66 (LV Subnet) with Local Internet breakout																														
		isInNet(public_ip, "43.254.229.139", "255.255.255.255") ||	       	 				// Bulgari 47F temp office
		isInNet(public_ip, "58.37.39.178", "255.255.255.255")								// INC0025798 Celine SDWAN Users	
	)			
	P66Network = "TRUE";
	
	var PZEN1 = "103.211.119.130:80";
	var PZEN2 = "185.110.84.130:80";
	
	var INTERNAL_PZEN1 = "emea-private-zscaler.proxy.lvmh:443";
	var INTERNAL_PZEN2 = "secaucus-private-zscaler.proxy.lvmh:443";
	
	if ( PZEN1 == "185.110.85.50:80") INTERNAL_PZEN1 = "emea-private-zscaler.proxy.lvmh:443";
	if ( PZEN2 == "185.110.85.50:80") INTERNAL_PZEN2 = "emea-private-zscaler.proxy.lvmh:443";
	if ( PZEN1 == "185.110.84.130:80") INTERNAL_PZEN1 = "emea-private-zscaler.proxy.lvmh:443";
	if ( PZEN2 == "185.110.84.130:80") INTERNAL_PZEN2 = "emea-private-zscaler.proxy.lvmh:443";
	if ( PZEN1 == "192.55.191.178:80") INTERNAL_PZEN1 = "secaucus-private-zscaler.proxy.lvmh:443";
	if ( PZEN2 == "192.55.191.178:80") INTERNAL_PZEN2 = "secaucus-private-zscaler.proxy.lvmh:443";
	if ( PZEN1 == "103.211.119.130:80") INTERNAL_PZEN1 = "singapore-private-zscaler.proxy.lvmh:443";
	if ( PZEN2 == "103.211.119.130:80") INTERNAL_PZEN2 = "singapore-private-zscaler.proxy.lvmh:443";

	var proxy_pzen = "PROXY " + INTERNAL_PZEN1 + "; PROXY " + INTERNAL_PZEN2 + "; PROXY 58.220.95.15:9400" ;


		
	/************************************/
	/*									*/
	/* 			Common Bypass			*/
	/*									*/
	/************************************/


    /* Don't send non-FQDN or private IP auths to Zscaler */
	if	( isPlainHostName(host) || shExpMatch(host, "192.0.2.*") || privateIP.test(host))
	return "DIRECT";
	
	/* INC0231325 - RITM0082645 */
    if (
		dnsDomainIs(host, "edcsso.excise.go.th")  ||
		dnsDomainIs(host, "edclogin.excise.go.th") ||
		dnsDomainIs(host, "excise.go.th")  
		
		)
	return "PROXY sin4.sme.zscloud.net:443; DIRECT";	
    /* INC0231325 - RITM0082645 End */

	/* RITM0081754 INC0209709 Redirect orion-qa.sephora.com to ZPA for Sephora */
	if 	(
		shExpMatch(host, "orion-qa.sephora.com")                             // RITM0081754
		)
		{
	    return "DIRECT";
	    }
    /* RITM0081754 INC0209709 END Redirect orion-qa.sephora.com to ZPA for Sephora */
 if (
        (
        (isInNet(myIpAddress(), "10.201.64.0", "255.255.254.0"))
         )
        &&
        ( 
        (dnsDomainIs(host,"qq.com"))	       ||
        (shExpMatch(host, "*.qq.com"))  ||
        (dnsDomainIs(host,".qq.com"))	       ||    
        (shExpMatch(host, ".qq.com"))  ||
        (dnsDomainIs(host,"wxapp.tc.qq.com"))  ||    
        (shExpMatch(host, "wxapp.tc.qq.com"))  ||
        (dnsDomainIs(host,"extshort.weixin.qq.com")) ||
        (shExpMatch(host, "extshort.weixin.qq.com"))  ||
        (dnsDomainIs(host,"minorshort.weixin.qq.com")) ||
        (shExpMatch(host, "minorshort.weixin.qq.com"))  ||
		(isInNet(host, "182.254.116.0", "255.255.255.0")) ||
		(isInNet(host, "182.254.118.0", "255.255.255.0")) ||
		(dnsDomainIs(host,".weixinbridge.com"))	       ||    
        (shExpMatch(host, ".weixinbridge.com"))  ||
		(dnsDomainIs(host,"servicewechat.com"))	       ||    
        (shExpMatch(host, "servicewechat.com"))  ||
		(dnsDomainIs(host,".qlogo.cn"))	       ||    
        (shExpMatch(host, ".qlogo.cn")) 
        )
        )
	return "PROXY sha2.sme.zscaler.net:443; PROXY bjs3.sme.zscloud.net:443; DIRECT";
	
	/* Bypass for IdP */
	if 	(
		dnsDomainIs(host, "adfs.bulgari.com") ||
		dnsDomainIs(host, "adfs40.bulgari.com") ||
		dnsDomainIs(host, "services.givenchy.com") ||   									// ADFS Givenchy - Split DNS
	    dnsDomainIs(host, "services.givenchy.fr") || 										// ADFS Givenchy - Split DNS
		dnsDomainIs(host, ".chic.lvmh.com") ||
		dnsDomainIs(host, "services.lvmh.fr") ||
		dnsDomainIs(host, "adfs.lvmhwj.com") || 
		dnsDomainIs(host, "saml.moet-hennessy.net") 
		)
	return "DIRECT";
	
	
    /* Bypass for VPN connections*/
    if 	(
		dnsDomainIs(host, "2.229.45.61")|| 													// VPN FENDI IT vpnpdc.fendi.com
		dnsDomainIs(host, "5.2.197.252") ||													// VPN Partner Rossimoda
		dnsDomainIs(host, "12.166.46.140") ||												// Tiffany VPN
		dnsDomainIs(host, "12.166.46.150") ||												// Tiffany VPN
		dnsDomainIs(host, "31.10.196.4") ||													// INC0024927 - Bypass Global Protect VPN
		dnsDomainIs(host, "32.58.225.59") ||												// Tiffany VPN
		dnsDomainIs(host, "40.73.117.77") ||												// Tiffany VPN
		dnsDomainIs(host, "46.193.43.130") ||												// Hotel Management VPN - RITM0034067
		dnsDomainIs(host, "46.193.43.146") ||												// Hotel Management VPN - RITM0034067
		dnsDomainIs(host, "52.174.18.34") ||			
		dnsDomainIs(host, "77.193.138.90") ||												// Hotel Management VPN - RITM0034067
		dnsDomainIs(host, "88.213.255.249")	||                                  			// RITM0034658
		dnsDomainIs(host, "89.250.177.30") ||                                 			// Onboarding RVL VPN
		dnsDomainIs(host, "116.66.222.134")|| 												// OneVPN Okta APAC gateway    
		dnsDomainIs(host, "122.208.205.251")|| 												// Tiffany VPN
		dnsDomainIs(host, "124.195.210.37") ||												// Hotel Management VPN - RITM0034067
		dnsDomainIs(host, "160.72.36.254") ||												// Tiffany VPN
		dnsDomainIs(host, "178.208.23.27") || 												// Fondation LV - RITM0029806 BBU 20210203
		dnsDomainIs(host, "192.34.213.210")|| 												// Tiffany VPN
		dnsDomainIs(host, "194.51.234.177")|| 												// VPN SSL Tanneries Roux
		dnsDomainIs(host, "194.250.201.1")|| 												// VPN SSL Cheval Blanc Paris
		dnsDomainIs(host, "195.101.145.18") ||												// Hotel Management VPN - RITM0034067
		dnsDomainIs(host, "196.61.214.139") ||												// Tiffany VPN
		dnsDomainIs(host, "192.55.191.97") ||			
		dnsDomainIs(host, "192.55.191.98") ||			
	    dnsDomainIs(host, "192.55.191.99") ||			
	    dnsDomainIs(host, "192.55.191.100") ||			
	    dnsDomainIs(host, "192.55.191.101") ||			
	    dnsDomainIs(host, "192.55.191.102") ||			
	    dnsDomainIs(host, "103.211.118.107") ||                                 			// RITM0035045
	    dnsDomainIs(host, "185.48.100.214") ||                                 			// Onboarding RVL VPN
	    dnsDomainIs(host, "194.177.112.64")	||                                  			// RITM0035189
	    dnsDomainIs(host, "194.3.170.9")	||                                  			// RITM0064991 Hotel Management VPN - Orange
		dnsDomainIs(host, "ras-emea.christiandior.fr") ||									// CDC VPN SSL
		dnsDomainIs(host, "vpn.emiliopucci.com") ||											// Pucci VPN SSL
		dnsDomainIs(host, "vpn.fendi.com") ||			
		dnsDomainIs(host, "vpn2.fendi.com") ||			
		dnsDomainIs(host, "vpn2ext.fendi.com") ||				
		dnsDomainIs(host, "vpnext.fendi.com") ||					
		dnsDomainIs(host, "vpnpdc.fendi.com") ||			
		dnsDomainIs(host, "remote-cloudops.generix.biz") ||                     			// RITM0031873
		dnsDomainIs(host, "vpn.halley-technologies.ch")  	||								// INC0026599
		dnsDomainIs(host, "access.hublot.com") ||			
		dnsDomainIs(host, "drp.hublot.com") ||			
		dnsDomainIs(host, "vpn.litis.com") ||			
		dnsDomainIs(host, "vpn.loropianany.com") ||			
		dnsDomainIs(host, "partners.lvmh.fr") || 											// RITM0025758
		dnsDomainIs(host, ".mjicloud.com") || 												// MJ VPN gateway
		dnsDomainIs(host, ".mjremote.com") || 												// MJ VPN gateway
		dnsDomainIs(host, "vpn.rossimoda.com") ||			
		dnsDomainIs(host, "remote.sephora.com")  ||											// Sephora US VPN gateway
		dnsDomainIs(host, "remote-fsc.sephora.com") || 										// Sephora US VPN gateway
		dnsDomainIs(host, "vpn-fr.thelios.com") ||						        			// Thelios VPN
		dnsDomainIs(host, "drremote.tiffany.com") ||										// Tiffany VPN
		dnsDomainIs(host, "hkremote.tiffany.com") ||										// Tiffany VPN
		dnsDomainIs(host, "jpremote.tiffany.com") ||										// Tiffany VPN
		dnsDomainIs(host, "remote.tiffany.com") ||											// Tiffany VPN
		dnsDomainIs(host, "rscbremote.tiffany.com") ||										// Tiffany VPN
		dnsDomainIs(host, "rscremote.tiffany.com") ||										// Tiffany VPN
		dnsDomainIs(host, "ukremote.tiffany.com") ||										// Tiffany VPN
		dnsDomainIs(host, "vendorvpn.tiffany.com") ||										// Tiffany VPN
		dnsDomainIs(host, "azure-vpn.tiffany.cn") ||										// Tiffany VPN
		dnsDomainIs(host, "vpn.zenith-watches.com")  ||										// INC0024927 - Bypass Global Protect VPN 
        dnsDomainIs(host, "vpn.chateaudesclans.com")   ||                       			// RITM0034658
        shExpMatch(host, "77.238.20.246")     ||                           	    			// RITM0041752
        shExpMatch(host, "91.200.207.202")   ||                                 			// RITM0045420
        dnsDomainIs(host, "neu-cdfmgmtvpn-pkbrhkcwng.dynamic-m.com")  ||        			// RITM0045929 Bulgari Global Protect VPN
        dnsDomainIs(host, "lvmhcpcvpn.lvmh-pc.cn") ||                           			// RITM0045930 Bulgari AnyConnect VPN
        dnsDomainIs(host, "vpn-it.alpenite.com") ||                             			// RITM0052060 Fendi
        dnsDomainIs(host, "kassensichv.fiskaly.com") ||                         			// RITM0052060
        dnsDomainIs(host, "fiskaly.com")  	||				                    			// RITM0052060
		dnsDomainIs(host, "maia.fgcndigital.com")  		||		                			// RITM0055863
        dnsDomainIs(host, "192.0.4.10")  		||		                        			// INC0074294
        shExpMatch(host, "77.43.104.218")     ||                                            // RITM0061273 - Hotel Management VPN
        shExpMatch(host, "104.245.119.114")   ||                                            // RITM0062690 - Hotel Management VPN
        dnsDomainIs(host, "vpn1.thelios.com")   ||                                          // RITM0064155
        dnsDomainIs(host, "vpn2.thelios.com")   ||                                          // RITM0064155
        dnsDomainIs(host, "vpn-us1.thelios.com")  ||                                        // RITM0068137 - Thelios VPN
        shExpMatch(host, "sign.rest.eurocert.pl") ||                                        // RITM0069492-INC0105310
        shExpMatch(host, "ecsigner.eurocert.pl")  ||                                        // RITM0069492-INC0105310
        shExpMatch(host, "services.eurocert.pl")  ||                                        // RITM0069492-INC0105310
        shExpMatch(host, "crl.eurocert.pl")       ||                                        // RITM0069492-INC0105310
        shExpMatch(host, "crl-b.eurocert.pl")     ||                                        // RITM0069492-INC0105310
        shExpMatch(host, "portal.eurocert.pl")    ||                                        // RITM0069492-INC0105310
        shExpMatch(host, "85.42.109.36")          ||                                        // RITM0069548
        dnsDomainIs(host, "192.0.4.52")           ||                                      	// RITM0075232
        dnsDomainIs(host, "194.51.172.140")       ||                                        // RITM0078169
        dnsDomainIs(host, "hds.myeasyoptic.com")  ||                                        // RITM0080387
        dnsDomainIs(host, "brsgp.tiffany.com")    ||                                        // RITM0084413
        dnsDomainIs(host, "areaonline.fr")        ||                                        // RITM0086024
        dnsDomainIs(host, "csa.lentyard.feadship.nl")                     ||           // RITM0092823
        dnsDomainIs(host, "178.16.160.254")                                                 // Hotel Management VPN - RITM0089508
		)
    return "DIRECT";	
		
	/* Bypass Zscaler domains */
    if 	(
		dnsDomainIs(host, "trust.zscaler.com") ||
		dnsDomainIs(host, "trust.zscaler.net") ||
		dnsDomainIs(host, "trust.zscalerone.net") ||
		dnsDomainIs(host, "trust.zscalertwo.net") ||
		dnsDomainIs(host, "trust.zscloud.net")
		)
    return "DIRECT";
    
    /* Bypass local status pages for Meraki devices */
	if 	(
		dnsDomainIs(host, "ap.meraki.com") ||
		dnsDomainIs(host, "mx.meraki.com") ||
		dnsDomainIs(host, "my.meraki.com") ||
		dnsDomainIs(host, "setup.meraki.com") ||
		dnsDomainIs(host, "switch.meraki.com") ||
		dnsDomainIs(host, "wired.meraki.com") 
		)
    return "DIRECT";
	
	
	/* Bypass for Microsoft Connectivity tests */
    if 	(
		shExpMatch(host, "www.msftconnecttest.com")||
		shExpMatch(host, "ipv6.msftconnecttest.com")||
		shExpMatch(host, "www.msftncsi.com")||
		shExpMatch(host, "ipv6.msftncsi.com")       
		)
    return "DIRECT";


	/*Bypass for LVMH internal domains and sites */
	if 	(
		/* Internal domains */
		dnsDomainIs(host, ".diageo") || 													// from WS-WorlWide-Transition.pac
		dnsDomainIs(host, ".guinnessudv") || 												// from WS-WorlWide-Transition.pac
		dnsDomainIs(host, ".holdings") || 													// RITM0026132
		dnsDomainIs(host, ".lan") ||			
		dnsDomainIs(host, ".local") ||			
		dnsDomainIs(host, ".lvmh") ||				
		dnsDomainIs(host, "altea-services.cloud") || 										// request from Hublot
		dnsDomainIs(host, "bulgari.group") || 												// RITM0019637 - Internal Domain
		dnsDomainIs(host, "geminijako.bulgari.group") || 									// INC0037814 - Internal Domain
        dnsDomainIs(host, "stockenquiry.bulgari.group") || 									// INC0037814 - Internal Domain
		dnsDomainIs(host, ".cevcp.fr") || 													// from WS-WorlWide-Transition.pac
		dnsDomainIs(host, ".clublvmh-eboutique.fr") || 										// RITM0014700
		dnsDomainIs(host, ".crm-ampelos.biz") || 											// from WS-WorlWide-Transition.pac
		dnsDomainIs(host, ".datacash.com") || 												// from WS-WorlWide-Transition.pac
		dnsDomainIs(host, "fdap.com") ||			
		dnsDomainIs(host, "fdjp.com") ||				
		dnsDomainIs(host, "internal.kenzo.info") || 										// RITM0013230
		dnsDomainIs(host, "loud-project.com") || 											// INC0024171
		dnsDomainIs(host, "devepf.lvmh.com") || 											// RITM0014456
		dnsDomainIs(host, "group.lvmh.com") ||			
		dnsDomainIs(host, ".homa.lvmh.com") || 												// RITM0020451
		dnsDomainIs(host, "intepf.lvmh.com") || 											// RITM0014456
		dnsDomainIs(host, ".neteye.lvmh.com") ||											// RITM0028947 - LVMH Security Domain - Split DNS
		dnsDomainIs(host, "prdepf.lvmh.com") || 											// RITM0015951
		dnsDomainIs(host, "quaepf.lvmh.com") || 											// RITM0014456
		dnsDomainIs(host, "witness.lvmh.com") ||			
		dnsDomainIs(host, "y2-poc.lvmh.com") || 											// RITM0016028
		dnsDomainIs(host, "wifiguest.lvmh.fr") || 											// RITM0016708
		dnsDomainIs(host, "oag01-admin.marcjacobs.cloud") ||			
		dnsDomainIs(host, "intranet.marcjacobs.com") ||			
		dnsDomainIs(host, ".udv.com") || 													// from WS-WorlWide-Transition.pac
		dnsDomainIs(host, ".vuitton.net") || 												// RITM0026705
		dnsDomainIs(host, ".ws-web.com") || 												// from WS-WorlWide-Transition.pac
		dnsDomainIs(host, "remotesales-bo.loropiana.cn") ||                     			// RITM0050501
		dnsDomainIs(host, "start-ws-sts-cn.lb.celine.cn") ||                    			// INC0066142
        dnsDomainIs(host, "start-ws-sts-cn-int.lb.celine.cn") ||                			// INC0066142
        dnsDomainIs(host, "dci-internal.mhd.com.cn") ||                         			// RITM0055057
        dnsDomainIs(host, "dci-internal-test.mhd.com.cn") ||                    			// RITM0055057
        dnsDomainIs(host, "cegid21-cn-prp.berluti.lvmh") ||                     			// RITM0058090
        dnsDomainIs(host, "cegid21-cn-it-prp.berluti.com") ||                   			// RITM0058697
        dnsDomainIs(host, "orion-dev.sephora.com") ||                           			// RITM0059472
        dnsDomainIs(host, "orion.sephora.com") ||                               			// RITM0059472
        dnsDomainIs(host, "cegid21-it.berluti.com") ||                          			// RITM0059508
        dnsDomainIs(host, "rdweb.prod.sap.24s.com/*") ||                                    // RITM0064338
        dnsDomainIs(host, "rdweb.staging.sap.24s.com/*") ||                                 // RITM0064338
        dnsDomainIs(host, "biaprdapp01.mac-erp.net")     ||                                 // RITM0070305
        dnsDomainIs(host, "ebsprdapp01.mac-erp.net")     ||                                 // RITM0070305
        dnsDomainIs(host, "retprdapp02.mac-erp.net")     ||                                 // RITM0070305
        dnsDomainIs(host, "retprdapp01.mac-erp.net")     ||                                 // RITM0070305
        dnsDomainIs(host, "oidprdmgtapp01.mac-erp.net")  ||                                 // RITM0070305
        dnsDomainIs(host, "concur-rpa.mhd.com.cn")       ||                                 // RITM0077262
        dnsDomainIs(host, "salescampaign.pucci.com")       ||                             // RITM0083082
        dnsDomainIs(host, "invoicing.mhd.com.cn")        ||                                 // RITM0077753
        dnsDomainIs(host, "pucemy2c04p.intranet.pucci.it")        ||                                 // INC0209986
        dnsDomainIs(host, "promohub.mhd.com.cn")        ||                                  // RITM0080281
		/* END Internal domains */			
					
		/* LVMH external ressources */			
		shExpMatch(host, "159.43.97.102") ||                       							// LHM DACS 
		dnsDomainIs(host, ".cmie.asso.fr") || 			
		dnsDomainIs(host, "admin-prod.chevalblanc.com") || 			
		dnsDomainIs(host, "cloud11.contact-world.net") || 									// RITM0017590
		dnsDomainIs(host, "cloud8.contact-world.net") || 									// RITM0017590
	//	dnsDomainIs(host, "lvmh.condecosoftware.com") || 									// RITM0018369
		dnsDomainIs(host, ".lounge-privee.com") || 											// RITM0014298
		dnsDomainIs(host, ".lvmhappening.com") || 											// RITM0014928
		dnsDomainIs(host, ".mhinnovationawards.com") ||			
		dnsDomainIs(host, ".mhinnovationawards2013.com") ||			
		dnsDomainIs(host, ".mhmedialib.com") ||			
		dnsDomainIs(host, ".mhps.fr") || 													// from WS-WorlWide-Transition.pac
		dnsDomainIs(host, ".int.microsdc.com") || 											// RITM0013921
		dnsDomainIs(host, "fresh-dev.neolane.net") ||			
		dnsDomainIs(host, "fresh-s.neolane.net") ||			
		dnsDomainIs(host, ".opera.int") ||			
		shExpMatch(host, "dv-eu-prod.sentinelone.net") || 									// Sentinel One
		shExpMatch(host, "euce1-lvmh.sentinelone.net") || 									// Sentinel One
		shExpMatch(host, "ioc-gw-eu.sentinelone.net") || 									// Sentinel One
		shExpMatch(host, "ioc-gw-cp-eu.sentinelone.net") || 								// Sentinel One
		shExpMatch(host, "ioc-gw-prod-eu-1a.sentinelone.net") || 							// Sentinel One
		shExpMatch(host, "ioc-gw-prod-eu-1b.sentinelone.net") || 							// Sentinel One
		shExpMatch(host, "ioc-gw-prod-eu-1c.sentinelone.net") || 							// Sentinel One
		dnsDomainIs(host, "www.sidetrackchicago.com") || 									// CHG0038361
		dnsDomainIs(host, ".whatismyip.com") ||
		dnsDomainIs(host, "djponline.pajak.go.id")    ||                                      // RITM0065996
		dnsDomainIs(host, "mercantil.nexx.app.br")    ||                                     // RITM0075233
		dnsDomainIs(host, ".prod.do.dsp.mp.microsoft.com")  ||                                 // RITM0075238 
		dnsDomainIs(host, "amlsurvey.moci.gov.qa")                                             // RITM0087029
		/* END LVMH external ressources */
		)
    return "DIRECT";

		/* For domains used both internally and externally check name resolution */
	if 	((
		dnsDomainIs(host, ".belmond.com") ||												// Belmond Split DNS
		dnsDomainIs(host, "celine.net") ||													// Celine Split DNS
		dnsDomainIs(host, ".fendi.com") ||													// Fendi Split DNS
		dnsDomainIs(host, ".hublot.com") ||													// Hublot Split DNS
		dnsDomainIs(host, ".lvmh-pc.com") ||												// P&C Split DNS
		dnsDomainIs(host, ".sephora.cn") ||													// Sephora Asia Split DNS
		dnsDomainIs(host, ".sephora-asia.com") ||											// Sephora Asia Split DNS
		dnsDomainIs(host, ".sephora.com") ||												// Sephora Split DNS
		dnsDomainIs(host, ".tiffany.cn") ||													// RITM0051171 - Tiffany Split DNS
		dnsDomainIs(host, ".tiffany.com") 													// Tiffany Split DNS
		) 
		&&
		(
		privateIP.test(dnsResolve(host))
		))
	return "DIRECT";
																				
		
        
        


	/********************************/
	/*								*/
	/* 		Bypass by Maison		*/
	/*								*/
	/********************************/
	
	if 	(
	
	    /* Belmond */
	    dnsDomainIs(host, "p-ita-zta-app01.belmond.com") ||                     			// Belmond HR app on Azure
	    dnsDomainIs(host, "peru.blsspainglobal.com") || 	                                //RITM0086850
		dnsDomainIs(host, ".hms.eu1.inforcloudsuite.com") ||                    			// Performance issue for Belmond booking app
		dnsDomainIs(host, ".hms.inforcloudsuite.com") || 					    			// Performance issue for Belmond booking app
		shExpMatch(url, "*.incontact.com") || 	    // RITM0090775
        shExpMatch(url, "*.nice-incontact.com") || 	// RITM0090775
		/* END Belmond */			
					
		/* Berluti */			
	//	dnsDomainIs(host, "oms.fgcndigital.com") || 			
		dnsDomainIs(host, "vapevents.alteva.eu") || 										// RITM0020693
		dnsDomainIs(host, "berluti.zportal.it") ||
		dnsDomainIs(host, "prefecturedepolice.interieur.gouv.fr") ||                        // RITM0069906
		dnsDomainIs(host, "cegid21-cn-it-prp.berluti.com") ||                    // RITM0071781
        dnsDomainIs(host, "cegid21-cn-it.berluti.com") ||                        // RITM0071781
        dnsDomainIs(host, "cegid21-it-prp.berluti.com") ||                       // RITM0071781
        dnsDomainIs(host, "cegid21-it.berluti.com") ||                           // RITM0071781
        dnsDomainIs(host, "cegid21-tmp-prp.berluti.com") ||                      // RITM0071781
		/* END Berluti */			
					
		/* Bulgari */			
		dnsDomainIs(host, ".bulgari.com") || 												// Bulgari Internal domain
		dnsDomainIs(host, "access.kfsd.gov.kw") || 											// Restricted to Kuweit
		dnsDomainIs(host, "aml.moci.gov.kw") || 											// Restricted to Kuweit
		dnsDomainIs(host, "eapp.moci.gov.kw") || 											// Restricted to Kuweit
		dnsDomainIs(host, "eco.moci.gov.kw") || 											// Restricted to Kuweit
		dnsDomainIs(host, "ereg.moci.gov.kw") || 											// Restricted to Kuweit
		dnsDomainIs(host, "gold.moci.gov.kw") || 											// Restricted to Kuweit
		dnsDomainIs(host, "kbc.moci.gov.kw") || 											// Restricted to Kuweit
		dnsDomainIs(host, "trademark.moci.gov.kw") || 										// Restricted to Kuweit
		dnsDomainIs(host, "insonline.moh.gov.kw") || 										// Restricted to Kuweit
		dnsDomainIs(host, "www.paci.gov.kw") || 											// Restricted to Kuweit
		dnsDomainIs(host, "inc.moci.gov.kw") || 											// Restricted to Kuweit
		dnsDomainIs(host, "ds556.awmdm.com") || 											// RITM0036774
		/* END Bulgari */			
					
		/* CDC */			
		dnsDomainIs(host, ".atelier-modele.fr") ||			
		dnsDomainIs(host, "bedior.christiandior.fr") || 									// RITM0017549 - CDC - IP Whitelisting
		dnsDomainIs(host, "diorknow.christiandior.fr") || 									// RITM0017549 - CDC - IP Whitelisting
		dnsDomainIs(host, "diorretail.christiandior.fr") || 								// RITM0017549 - CDC - IP Whitelisting
		dnsDomainIs(host, "iforgot.christiandior.fr") || 									// RITM0019572 - CDC - IP Whitelisting
		dnsDomainIs(host, "cdprod.servicepoint.multiproduction.fe.fluentcommerce.com") || 	// INC0043702
		dnsDomainIs(host, "cdprod.servicepoint.fluentretail.com") || 						// INC0043702
		dnsDomainIs(host, "uat-bedior.christiandior.fr") || 								// RITM0017549 - CDC - IP Whitelisting
		dnsDomainIs(host, "uat-diorknow.christiandior.fr") || 								// RITM0017549 - CDC - IP Whitelisting
		dnsDomainIs(host, "uat-diorretail.christiandior.fr") || 							// RITM0017549 - CDC - IP Whitelisting
		dnsDomainIs(host, "neolane.dior.com") || 											// RITM0024858 - CDC - IP Whitelisting
		dnsDomainIs(host, "dior.fashion") || 				                    			// RITM0036337 - CDC - IP Whitelisting
		dnsDomainIs(host, ".eu.dior.fashion") ||											// CDC Internal domain
		dnsDomainIs(host, ".amis.bradfordswissport.com") ||                     			// INC0040366
		dnsDomainIs(host, "n249.network-auth.com") ||                           			// INC0049386
		dnsDomainIs(host, ".empowertime.com") ||			
		shExpMatch(host, "selfservis.yurticikargo.com")    ||                   			// RITM0059012
		dnsDomainIs(host, "dmdk.ru")            ||                           		        // RITM0070030
		dnsDomainIs(host, "fedsfm.ru")          ||                           		        // RITM0070030
        dnsDomainIs(host, "portal.fedsfm.ru")   ||                           		        // RITM0070030
        dnsDomainIs(host, "customs.gov.ru")     ||                           		        // RITM0070030
        dnsDomainIs(host, "nalog.gov.ru")       ||                           		        // RITM0070030
        dnsDomainIs(host, "markirovka.crpt.ru") ||                           		        // RITM0070030
        dnsDomainIs(host, "edata.customs.ru")   ||                           		        // RITM0070030
        dnsDomainIs(host, "lkul.nalog.ru")      ||                           		        // RITM0070030
        dnsDomainIs(host, "lk.dmdk.ru")         ||                           		        // RITM0070030
        dnsDomainIs(host, "cbr.ru")             ||                           		        // RITM0070030
        dnsDomainIs(host, "lkulgost.nalog.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "lkul.nalog.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "sfr.gov.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "www.nalog.gov.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "digital.gov.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "rkn.gov.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "archives.gov.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "fssp.gov.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "fsa.gov.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "customs.gov.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "edata.customs.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "login.mos.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "www.gosuslugi.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "portal.fedsfm.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "my.beeline.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "sso.megafon.ru")             ||                            // RITM0078864
        dnsDomainIs(host, "188.254.86.136")             ||                            // RITM0078864
		/* END CDC */			
					
		/* CSC */			
		dnsDomainIs(host, "loud-iris-prod.azurewebsites.net") ||			
		dnsDomainIs(host, "colis-logistique.com") ||			
       	dnsDomainIs(host, "colissimo.entreprise.laposte.fr") ||			
		/* END CSC */			
					
		/* Celine */			
		dnsDomainIs(host, "c-care.celine.net") ||                               			// RITM0031608
		dnsDomainIs(host, "algo-api-em-uat.celine.net") ||                      			// INC0033073
		dnsDomainIs(host, "algo-api-em-dev.celine.net") ||                      			// INC0033104
		dnsDomainIs(host, "nexthink.celine.net") ||                             			// INC0031440
		dnsDomainIs(host, "celineonline.crm4.dynamics.com") ||				
		dnsDomainIs(host, ".madb.europa.eu") ||												// INC0025241 (temporary)
		dnsDomainIs(host, "celine.eu.nexthink.cloud") ||                        			// INC0031440
		dnsDomainIs(host, "celine-engine-1.eu.nexthink.cloud") ||               			// INC0031440
		dnsDomainIs(host, "gateway-celine.eu.goskope.com") ||                      			// RITM0065590
		dnsDomainIs(host, "download-celine.eu.goskope.com") ||                      		// RITM0065590
		dnsDomainIs(host, "achecker-celine.eu.goskope.com") ||                      		// RITM0065590
		dnsDomainIs(host, "sfchecker.goskope.com") ||                               		// RITM0065590
		dnsDomainIs(host, "nsauth-celine.eu.goskope.com") ||                               	// RITM0065590
		dnsDomainIs(host, "gateway.gslb.goskope.com") ||                                   	// RITM0065590
		dnsDomainIs(host, "zucchetti.celine.net")    ||                   	                // RITM0085790
		/* END Celine */			
					
		/* DFS */			
		dnsDomainIs(host, "bigticket.ae") || 												// SDM 21896
		dnsDomainIs(host, ".dfs.com") || 													// DFS Split DNS	
		dnsDomainIs(host, ".dfs")||					 										// DFS internal domain
		dnsDomainIs(host, ".dfsgroup.com")||			
		dnsDomainIs(host, ".dfspos.com")||													// DFS internal domain
		dnsDomainIs(host, ".dfspartner.com")||		
		dnsDomainIs(host, ".fxall.com") ||													// SDM738061												   
		dnsDomainIs(host, "made2order.newworld.co.nz") || 									// SDM 876830
		dnsDomainIs(host, ".tax.gov.kh") || 												// SDM number to be added
		dnsDomainIs(host, ".guam.gov") ||						   			
		dnsDomainIs(host, ".hawaii.gov") || 												// Spirit CHN-953
		dnsDomainIs(host, ".landesk.com") ||			
		dnsDomainIs(host, ".smartborder.com") ||			
		dnsDomainIs(host, ".dfs-rollout-dfs-sit.co-mall.com") ||
		dnsDomainIs(host, ".hireGuam.com")||                                               //INC0282747
		shExpMatch(host, "dfs-rollout-dfs-sit.co-mall.com") ||			
		/* END DFS */			
					
		/* FENDI */			
		dnsDomainIs(host, "lglrr.cloud.bit") ||												// Fendi internal domain
		dnsDomainIs(host, ".fndservice.it") ||												// Fendi internal domain
		dnsDomainIs(host, "sapi.clo3d.com") ||                             					// INC0039857
		dnsDomainIs(host, "sapi.clo3d-china.com") ||                       					// INC0039857
		dnsDomainIs(host, ".clo-set.com") ||                               					// INC0039857
		dnsDomainIs(host, "pknet2.intesasanpaolo.com") 		||								// RITM0037999
		dnsDomainIs(host, "vpbx-matisse.iptelecom.it") 		||								// RITM0044608
		shExpMatch(url, "www.m.me/login/?next=https://m.me/301701851577") || 	            // RITM0065374
		dnsDomainIs(host, "*.niceincontact.com") 	||                                       // RITM0087047
		/* END FENDI */				
			
		/* FG */			
		dnsDomainIs(host, "v.sf-express.com") ||											// INC0026630 - recommended by Zscaler support
		dnsDomainIs(host, "themills.com.hk") ||							    				// INC0027205
		/* END FG */				
			
		/* Fondation */ 			
		dnsDomainIs(host, "app.sendinblue.com") ||											// Incident with sending Blue application - authentication fails - 110919
		dnsDomainIs(host, "my.sendinblue.com") ||											// Incident with sending Blue application - authentication fails - 110919
		/* END Fondation */			
					
		/* HLD */ 			
		dnsDomainIs(host, "lvmhprize.com") ||												// RITM0028262_20200911_RAD
		dnsDomainIs(host, "dld.mykds.com") ||                          						// RITM0029133
		dnsDomainIs(host, "prdld.mykds.com") ||                         					// RITM0029133	
		shExpMatch(host, ".print.subprint.io") ||                                          // INC0107252
		dnsDomainIs(host, "print.subprint.io") ||                                          //INC0107252
		/* END HLD*/			
					
		/* GIVENCHY */			
		dnsDomainIs(host, ".apac.givenchy.com")	|| 											// Givenchy internal domain - RITM0027477
		dnsDomainIs(host, ".china.givenchy.com")||                      					// Givenchy internal domain - RITM0029440
		dnsDomainIs(host, "docs.givenchy.com")	|| 											// Givenchy internal domain - RITM0029476
		dnsDomainIs(host, ".emea.givenchy.com")	|| 											// Givenchy internal domain - RITM0027477
		dnsDomainIs(host, ".us.givenchy.com")	|| 											// Givenchy internal domain - RITM0027477
		/* END GIVENCHY */			
					
		/* HUBLOT */			
		dnsDomainIs(host, "author-p45802-e212388.adobeaemcloud.com") || 					// RITM0035388
		dnsDomainIs(host, "author-p45802-e227660.adobeaemcloud.com") || 					// RITM0035388
		dnsDomainIs(host, "author-p45802-e227661.adobeaemcloud.com") || 					// RITM0035388
		dnsDomainIs(host, "publish-p45802-e212388.adobeaemcloud.com") || 					// RITM0035388
		dnsDomainIs(host, "publish-p45802-e227660.adobeaemcloud.com") || 					// RITM0035388
		dnsDomainIs(host, "publish-p45802-e227661.adobeaemcloud.com") || 					// RITM0035388
		dnsDomainIs(host, ".hublot.ch") ||		
		dnsDomainIs(host, "dev-echo.hublot.com") || 										// RITM0035388
		dnsDomainIs(host, "echo.hublot.com") || 											// RITM0035388
		dnsDomainIs(host, "staging-echo.hublot.com") || 									// RITM0035388							
		dnsDomainIs(host, "proconcept-eu.hublot.com") || 									// Internal resources for VPN access
		dnsDomainIs(host, "proconcept-hq.hublot.com") || 									// Internal resources for VPN access
		dnsDomainIs(host, "proconcept-us.hublot.com") || 									// Internal resources for VPN access
		dnsDomainIs(host, "sellout-wa.hublot.com") ||										// Hublot Incident with Wesekey Authenticate Tool - 050619																				   																								  
		dnsDomainIs(host, "wisekey.com") ||													// Hublot Incident with Wesekey Authenticate Tool - 050619
		dnsDomainIs(host, "wechselgeld.post.at") ||											// INC0056335
		dnsDomainIs(host, "authenticate.wiseauthentic.com") ||								// Hublot Incident with Wesekey Authenticate Tool - 050619
		dnsDomainIs(host, "auth.services.adobe.com") ||										// RITM0035094
		dnsDomainIs(host, "sophiemallebranche.com") ||										// RITM0065098
		/* END HUBLOT */
		
		/* HOTEL MANAGEMENT */
        dnsDomainIs(host, "mtce2.oraclehospitality.eu-frankfurt-1.ocs.oraclecloud.com")	||	//RITM0063023
        /* END HOTEL MANAGEMENT */
        
        /* Heng Long */ 
        dnsDomainIs(host, "212.19.118.190") || 		// RITM0070384
        /* END Heng Long */
					
					
		/* KENZO */			
		dnsDomainIs(host,".kenzo.lvmh") ||			
		dnsDomainIs(host,"api-int-test.kenzo.info") ||			
		dnsDomainIs(host,"internal2.kenzo.info") ||			
        /* END KENZO */			
					
			
		/* LOEWE */			
		shExpMatch(host, "217.138.168.26") || 																  
		dnsDomainIs(host, ".es.loewe") ||			
		dnsDomainIs(host, ".loewe.app") || 			        								// RITM0036291 - Internal Domain
		dnsDomainIs(host, "loeweintranet.com") || 											// RITM0020095 - Internal Domain
		dnsDomainIs(host, "salesforce.loewe.com")||			
		dnsDomainIs(host, "loewe.com.cn") ||			
        /* END LOEWE */					
			
		/* Loropiana */			
	//	dnsDomainIs(host, "loropiana.zucchetti.com") ||										// Performance issues through Zscaler	
		dnsDomainIs(host, ".lp.corp") ||													// Internal Domain	
		dnsDomainIs(host, ".loropiana.com") || 												// Loropiana Split DNS
        /* END Loropiana */	
			
		/* LVMH HLD Samaritaine */
		dnsDomainIs(host, "cloud.realiz3d.fr") || //RITM0018036 - Bypass for direct access	
		shExpMatch(host, "*mycloud3D-neo-vm00.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		shExpMatch(host, "*mycloud3D-neo-vm01.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		shExpMatch(host, "*mycloud3D-neo-vm02.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		shExpMatch(host, "*mycloud3D-neo-vm03.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		shExpMatch(host, "*mycloud3D-neo-vm04.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		shExpMatch(host, "*mycloud3D-neo-vm05.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		shExpMatch(host, "*mycloud3D-neo-vm06.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		shExpMatch(host, "*mycloud3D-neo-vm07.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		shExpMatch(host, "*mycloud3D-neo-vm08.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		shExpMatch(host, "*mycloud3D-neo-vm09.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		shExpMatch(host, "*mycloud3D-neo-vm10.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		shExpMatch(host, "*mycloud3D-neo-vm11.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		shExpMatch(host, "*mycloud3D-neo-vm12.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		shExpMatch(host, "*mycloud3D-neo-vm13.cloudgaming.pro") || 							// RITM0018036 - Bypass for direct access
		/* END LVMH HLD Samaritaine */				
					
		/* Les Echos */				
		isInNet(dnsResolve(host), "91.194.100.237", "255.255.255.255") ||				
		shExpMatch(host, "46.227.80.170") || 												// RITM0021938
		dnsDomainIs(host, "ac-lesechos-publishing.fr") || 									// RITM0021232
		dnsDomainIs(host, "agencesonline.com") || 											// INC0023997
		shExpMatch(host, "www.annonces-legales.fr") ||				
		shExpMatch(host, "pro.annonces-legales.fr") ||                          			// RITM0040289
		dnsDomainIs(host, "aujourdhui.fr") || 												// RITM0019116 - Entrées Host File Postes
		dnsDomainIs(host, "business.avast.com") || 											// INC0028849																			 
	//	shExpMatch(host, "*.boursier.com") || 												// RITM0021889 - ECHOS - RITM0066705
		shExpMatch(host, "boutique.capitalfinance.eu") ||				
		dnsDomainIs(host, "pr.bvdep.com") || 												// RITM0022423
		dnsDomainIs(host, "cardibox.spectacles.carrefour.fr") || 							// RITM0022806
		shExpMatch(host, "www.connaissancedesarts.com")||				
		dnsDomainIs(host, "covidradius.com") ||				
		dnsDomainIs(host, "dematis16.ecritel.net") || 										// RITM0021917
		dnsDomainIs(host, "disneyplus.com") || 												// INC0025322
		shExpMatch(host, "www.expertinfos.com")||				
		dnsDomainIs(host, "e-legalite.com") || 												// INC0024322
		dnsDomainIs(host, ".e-marchespublics.com") ||				
		dnsDomainIs(host, ".e-parapheur.com") || 										
		dnsDomainIs(host, "e-convocations.com") ||				
		dnsDomainIs(host, ".e-signaturesecurisee.com") || 										
		dnsDomainIs(host, "e-stockagesecurise.com") ||				
		shExpMatch(host, "*.groupelesechos.fr") ||				
		shExpMatch(host, "www.guidedelacreationdentreprise.com") ||				
		dnsDomainIs(host, "lesechos-audience.inbox.fr") ||									// RITM0017565
		dnsDomainIs(host, "lesechos-crm.inbox.fr")|| 										// RITM0016454
		dnsDomainIs(host, ".lesechosleparisien.fr") ||                          			// RITM0035429 - LELP Split DNS
		dnsDomainIs(host, "mt.inbox.fr") || 												// RITM0023576
		dnsDomainIs(host, "vac-lec.i-tracing.com") || 										// RITM0021917
		shExpMatch(host, "*.in.ladtech.fr") || 												// RITM0021889 - ECHOS
		dnsDomainIs(host, "lesechos.legisway.com") || 										// RITM0019997
		shExpMatch(host, "*.leparisien.fr") ||												// LELP Split DNS
	    dnsDomainIs(host, "asset-recette.parismatch.fr") ||		                            //RITM0086402
        dnsDomainIs(host, "timone-recette.parismatch.fr") ||		                        //RITM0086402
        dnsDomainIs(host, "murnum-recette.parismatch.fr") ||		                        //RITM0086402
        dnsDomainIs(host, "FotowareIM1-recette.parismatch.fr") ||	                        //RITM0086402
        dnsDomainIs(host, "FotowareIM2-recette.parismatch.fr") ||	                        //RITM0086402
        dnsDomainIs(host, "colorfactory-recette.parismatch.fr") ||	                        //RITM0086402
        dnsDomainIs(host, "switch-recette.parismatch.fr") ||		                        //RITM0086402	
		dnsDomainIs(host, "lerobert.com") || 												// RITM0024659
		dnsDomainIs(host, ".lesechos.fr") || 												// RITM0016459
		shExpMatch(host, "www.lesechosdelafranchise.com") ||				
		shExpMatch(host, "www.lesechosmedias.fr")||				
		dnsDomainIs(host, "lesechos-etudes.fr") ||											// RITM0016533 - LELP Split DNS
		shExpMatch(host, "*.lesechos-events.fr") ||											// LELP Split DNS 
		shExpMatch(host, "www.lesechos-publishing.fr") ||									// LELP Split DNS 
		dnsDomainIs(host, "livemixr.com") ||                                    			// Workaround CORS
		shExpMatch(host, "*.local.lprs1.fr") || 											// RITM0019668
		dnsDomainIs(host, "mairie-vigneux-sur-seine.fr") || 								// RITM0028031
		dnsDomainIs(host, "whatsonknowledgebase.mediagenix.tv") || 							// RITM0024867
		dnsDomainIs(host, ".adonis.mediapole.info") ||										// LELP Internal Domain
		dnsDomainIs(host, "s66.mynotilus.com") || 					    					// INC0029769
		dnsDomainIs(host, "leparisien.newsbridge.io ") || 					   				// RITM0041321
		dnsDomainIs(host, "lesechosleparisien.pixpalace.com") || 							// INC0023997
		dnsDomainIs(host, "qobuz.com") || 													// RITM0024646
		dnsDomainIs(host, "totabo-data1.fr1.quickconnect.to") || 							// RITM0025265
		dnsDomainIs(host, ".teamdiffusion.fr") ||											// LELP internal domain
		dnsDomainIs(host, "viry-chatillon.test-pellicam.com") || 							// INC0023620
		dnsDomainIs(host, "mezzo.playout.tvvideoms.com") || 								// RITM0025267
		dnsDomainIs(host, "villeneuve-saint-georges.fr") || 								// INC0023620
		dnsDomainIs(host, "ville-noisiel.fr") || 											// RITM0025848
		dnsDomainIs(host, "viry-chatillon.fr") || 											// INC0023620
		dnsDomainIs(host, ".france.tv") || 								        			// INC0034995
		dnsDomainIs(host, ".simulcast-p.ftven.fr") || 					        			// INC0034995
		dnsDomainIs(host, ".live-olympics.ftven.fr") || 					    			// INC0034995
		dnsDomainIs(host, ".play.adpaths.com") || 					            			// INC0034995
		dnsDomainIs(host, ".ftven.fr") || 					                    			// INC0034995
		dnsDomainIs(host, ".akamaihd.net") || 					                			// INC0034995
		dnsDomainIs(host, ".live-olympics.ftven.fr") || 			            			// INC0034995
		dnsDomainIs(host, ".lvmh.em-cms.cloud") || 			                    			// RITM0034887
		dnsDomainIs(host, ".val-doise.gouv.fr") ||                              			// INC0035002
	//	shExpMatch(host, "34.79.250.2")  || 												// RITM0048672
	//	dnsDomainIs(host, ".yuca.tv") ||                                        			// RITM0049028
	//	dnsDomainIs(host, ".streamakaci.tv") ||                                 			// RITM0049028
		dnsDomainIs(host, "cloud2-vcl.vivetic.com") ||                          			// RITM0054461	
		dnsDomainIs(host, "paris-paradis.leparisien.fr/wp-admin")      ||                   // RITM0064821
		shExpMatch(host, "*.efl.fr")                            ||                           // RITM0080177
		dnsDomainIs(host, "asset.parismatch.fr") ||                             //RITM0089268
        dnsDomainIs(host, "timone.parismatch.fr") ||                            //RITM0089268
        dnsDomainIs(host, "murnum.parismatch.fr") ||                            //RITM0089268
        dnsDomainIs(host, "switch-prod.parismatch.fr") ||                       //RITM0089268
        shExpMatch(host, "*.in.parismatch.fr") 		||          			    //RITM0089268
		/* END Les Echos */				
					
		/* Marc Jacobs */				
		shExpMatch(host, "90286538-retail-ondemand.cegid.cloud") ||             			// RITM0048473
		/* END Marc Jacobs */			
						
		/* MHIS */ 			
		/* REQ0020322-RITM0021638 */			
		shExpMatch(url, "http://5.153.45.155/*") || 										// RITM0026315 - Test portal for APP IHM
		dnsDomainIs(host, "catalog.belden.com") || 											// RITM0029535														  
		dnsDomainIs(host, "fiprofile.cdnpk.net") || 										// RITM0024663
		dnsDomainIs(host, ".jrioe.co.jp") ||                             					// INC0027538																		  
		dnsDomainIs(host, "rpc.pc-printer-discovery.wifi.creativecubes.co") || 				// RITM0030247
		dnsDomainIs(host, ".domperignon.com") || 											// from WS-WorlWide-Transition.pac
		dnsDomainIs(host, "achecker-mh.eu.goskope.com") ||				
		dnsDomainIs(host, "download.eu.goskope.com") ||				
		dnsDomainIs(host, "gateway-mh.eu.goskope.com") ||				
		dnsDomainIs(host, "sfchecker-mh.eu.goskope.com") ||				
		dnsDomainIs(host, ".int.hennessy.fr") || 											// from WS-WorlWide-Transition.pac
		dnsDomainIs(host, "hennessy8.com") || 												// RITM0014515
		dnsDomainIs(host, "thongkedoanhnghiep.gso.gov.vn") || 								// RITM0029424															   
		dnsDomainIs(host, "phpmyadmin.lvmh-lin3-web01-pub.lvmh.lbn.fr") || 					// RITM0029455
		dnsDomainIs(host, "phpmyadmin.lvmh-mhis-linwbddpp01-pub.lvmh.lbn.fr") ||		 	// RITM0029455
		dnsDomainIs(host, "phpmyadmin.lvmh-mhis-linweb01-pub.lvmh.lbn.fr") || 				// RITM0029455		
		dnsDomainIs(host, "cloud.letsignit.com") ||											// RITM0026529 - application "LetSignIt" doesn't work with ZScaler activated
		dnsDomainIs(host, "storage.letsignit.com") ||										// RITM0026529 - application "LetSignIt" doesn't work with ZScaler activated
		dnsDomainIs(host, "intranet-backend.mhd.com.cn") ||									// MHIS Split DNS
		dnsDomainIs(host, "intranet-new.mhd.com.cn") ||										// MHIS Split DNS
		dnsDomainIs(host, "intranet.mhd.com.cn") ||											// MHIS Split DNS
		dnsDomainIs(host, "phoenix-test.mhd.com.cn") ||										// INC0056160
		dnsDomainIs(host, "phoenix.mhd.com.cn") ||						    				// INC0056160
		dnsDomainIs(host, "codescan.mhd.com.cn") ||						    				// INC0056160
		dnsDomainIs(host, ".mhdicp.jp") ||				
		dnsDomainIs(host, ".mhusa.com") ||				
		dnsDomainIs(host, ".mhusa.net") ||                              					// RITM0029089
		dnsDomainIs(host, "mh-is.com") ||				
		dnsDomainIs(host, ".mh-servicedesk.biz") || 										// from WS-WorlWide-Transition.pac
		dnsDomainIs(host, ".mh-target.biz") || 												// from WS-WorlWide-Transition.pac
		dnsDomainIs(host, "api-ers.moethennessy.com") || 									// CHG0034634
		dnsDomainIs(host, "api-pp-ers.moethennessy.com") || 								// CHG0034634
		dnsDomainIs(host, "img-ecep.moethennessy.com")|| 									// RITM0013478
		dnsDomainIs(host, "img-pp-ecep.moethennessy.com") || 								// RITM0013478
		dnsDomainIs(host, "imhprovement.moethennessy.com")|| 								// RITM0025884																			 
		dnsDomainIs(host, ".moet-hennessy.biz") ||											// MHIS Split DNS
		dnsDomainIs(host, ".moet-hennessy.com") ||											// MHIS Split DNS
		dnsDomainIs(host, ".moet-hennessy.net") || 											// MHIS Split DNS
		dnsDomainIs(host, "nexxera.com") ||                                     			// INC0032263
		dnsDomainIs(host, "engetecpragas.com.br") ||                            			// INC0032268
		dnsDomainIs(host, "virk.dk") ||                                         			// INC0032481	
		dnsDomainIs(host, ".ign.fr") ||	                                        			// RITM0032309
		dnsDomainIs(host, "nguyco.antoancovid.vn") || 						    			// INC0033908
		dnsDomainIs(host, "vivo.com.br") || 						            			// RITM0034695
		dnsDomainIs(host, "elections-professionnelles.travail.gouv.fr") || 	    			// INC0053129 
		dnsDomainIs(host, "gov.ru") || 			                                			// RITM0034803 - MHIS
        dnsDomainIs(host, "gosuslugi.ru") || 			                        			// RITM0034803 - MHIS
        dnsDomainIs(host, "servicioswww.anses.gob.ar") || 			            			// INC0054599 - MHIS
        dnsDomainIs(host, "ana.gob.pa") || 			                            			// INC0054599 - MHIS
        dnsDomainIs(host, "mos.ru") || 			                                			// RITM0034803 - MHIS
        dnsDomainIs(host, "arbitr.ru") || 			                            			// RITM0034803 - MHIS
        dnsDomainIs(host, "my.rt.ru") || 		                            				// RITM0034803 - MHIS
		dnsDomainIs(host, "front-moet-chandon.viadirect.com") || 							// RITM0017817
		dnsDomainIs(host, "front-moet-chandon-2.viadirect.com") || 							// RITM0022939
		dnsDomainIs(host, "diageocontenthub.com") || 						    			// INC0037153
		dnsDomainIs(host, "prp.millesima.fr") ||                                			// INC0037171
		dnsDomainIs(host, "secweb.procergs.com") ||                             			// RITM0035401
		dnsDomainIs(host, "edi.carrefoursa.com") ||                             			// RITM0035401
		dnsDomainIs(host, "*-internal.mhd.com.cn") || 			                			// RITM0050359
		dnsDomainIs(host, "git-security.mhd.com.cn") || 			            			// RITM0050582
		dnsDomainIs(host, "gov.tr") ||			                                			// RITM0052930
		dnsDomainIs(host, "bssplugin.bssys.com") ||			                    			// RITM0055583
		dnsDomainIs(host, "edi.carrefoursa.com") ||                             			// RITM0058292
		dnsDomainIs(host, "edimiddle.carrefoursa.com") ||                       			// RITM0058348
		dnsDomainIs(host, "assinador.ac.rs.gov.br") ||                                      // RITM0058348
		dnsDomainIs(host, "ibank.crediteurope.ru") ||                                       // RITM0062680
		dnsDomainIs(host, "www.gso.gov.vn") ||                                              // RITM0069016
		dnsDomainIs(host, "mercantil.nexx.app.br") ||                                       //RITM0075233
		/* END MHIS */				
			
		/* P&C */				
		dnsDomainIs(host, "freshinc.campaign.adobe.com") ||									// RITM0025489 - P&C US FRESH CRM - ADOBE CAMPAIGN (Update)
		dnsDomainIs(host, "freshinc-mkt-prod1.compaign.adobe.com") ||						// RITM0025489 - P&C US FRESH CRM - ADOBE CAMPAIGN (Update)
		dnsDomainIs(host, "bridgepaynetsecuretx.com") || 									// RITM0024824
        dnsDomainIs(host, "www.bridgepaynetsecuretest.com") || 								// RITM0024778
		dnsDomainIs(host, ".app.dashhudson.com") || 										// INC0023628
		dnsDomainIs(host, ".diorus.com") ||			
		dnsDomainIs(host, "pcisfresh.lightning.force.com") || 								// RITM0028004
		dnsDomainIs(host, "t.email.fresh.com") ||											// RITM0025489 - P&C US FRESH CRM - ADOBE CAMPAIGN (Update)
		dnsDomainIs(host, "freshesales.com") || 											// RITM0025074
		dnsDomainIs(host, "paylink.itstgate.com") || 										// RITM0024778
	    dnsDomainIs(host, ".lvmhampc.com") || 												// RITM0024637
		dnsDomainIs(host, "lvmhmi9.com") || 												// Internal domain used by P&C US
        dnsDomainIs(host, "labeautybox.lvmh-fb.com") || 									// RITM0025433
        dnsDomainIs(host, "cloud.mediusflow.com") || 										// RITM0024678
        /* END P&C */				
					
		/* Partners */				
		dnsDomainIs(host, "givenchy.ajaris.com") ||				
		dnsDomainIs(host, ".alsid-dsc.io") ||  												// CHG0034533 - WhiteListing Public IP 
		dnsDomainIs(host, ".altaven.com") ||  												// RITM0012971 - WhiteListing Public IP 
		dnsDomainIs(host, "tsg.armadillo.fr") ||  											// RITM0025892
		dnsDomainIs(host, ".atosorigin.com") ||				
		dnsDomainIs(host, "extranet.banque-accord.fr") ||  									// RITM0016853
		dnsDomainIs(host, ".bjn.vc") ||				
		dnsDomainIs(host, ".bluejeans.com ") ||  											// RITM0018745 - WhiteListing Public IP 
		dnsDomainIs(host, ".cgi.com") ||  													// RITM0013356 - WhiteListing Public IP 
		dnsDomainIs(host, "remote.colliersabr.com") ||				
		dnsDomainIs(host, "st.concursolutions.com") ||				
		dnsDomainIs(host, "anywhere.diageo.com")|| 											// RITM0018336
		dnsDomainIs(host, "dyostem.com") || 												// RITM0012614
		dnsDomainIs(host, ".ecce.fr") ||					
	//	dnsDomainIs(host, ".efl.fr") ||  													// RITM0013066 - WhiteListing Public IP - RITM0078116
		dnsDomainIs(host, ".euroclear.com") ||  											// RITM0012986 - WhiteListing Public IP 
		dnsDomainIs(host, "portal.euromonitor.com") ||										// RITM0020573 - WhiteListing Public IP 
		dnsDomainIs(host, "givenchy.gibra.com") ||				
		dnsDomainIs(host, "gibra.fr") ||				
		dnsDomainIs(host, "gerermesressourceshumaines.groupesfc.fr") ||						// RITM0014345
		dnsDomainIs(host, ".meta4.fr") ||  													// RITM0012959 - WhiteListing Public IP
		dnsDomainIs(host, "mh-targetnoprd.biz") ||				
		dnsDomainIs(host, ".mintel.com") ||  												// RITM0013607 - WhiteListing Public IP 
		dnsDomainIs(host, "ftp.mission-media.co.uk") ||				
		dnsDomainIs(host, "forex.ebusiness.mizuhocbk.co.jp") ||				
		dnsDomainIs(host, ".moneticien.com") ||  											// RITM0013850 - WhiteListing Public IP
		dnsDomainIs(host, ".mozy.com") || 													// from WS-WorlWide-Transition.pac
		dnsDomainIs(host, "e-tax.nta.go.jp") ||					
	//	dnsDomainIs(host, "easyshare.oodrive.com") ||				
	//	dnsDomainIs(host, "sharing.oodrive.com") ||				
		dnsDomainIs(host, "asp8.poscm.com") ||				
		dnsDomainIs(host, ".quable.io") ||  												// RITM0021373 - WhiteListing Public IP 
		dnsDomainIs(host, "rctsystems.com")||				
		dnsDomainIs(host, "silaexpert01.fr") ||  											// RITM0016917 - WhiteListing Public IP
		dnsDomainIs(host, ".sirh-saas.fr") ||  												// RITM0012959 - WhiteListing Public IP 
		dnsDomainIs(host, "portal.sunriseconsult.com") ||				
		dnsDomainIs(host, "csec.esav-preprod.claranet.utopix.ch") ||				
		dnsDomainIs(host, ".worldline.com") ||  											// RITM0013238 - WhiteListing Public IP 
		/* END Partners */				
					
		/* RIMOWA */				
		dnsDomainIs(host, "sys.staging.efulfilment.de") || 									// RITM0026988
		dnsDomainIs(host, "rimowa-prd.legisway.com") || 									// RITM0026861
		dnsDomainIs(host, ".internal.rimowa.com") || 										// RITM0023753 - Internal Domain
		dnsDomainIs(host, "rimdevfpas.rimowa.com") || 										// RITM0026865
		dnsDomainIs(host, "rimprdfpas.rimowa.com") || 										// RITM0026864
		dnsDomainIs(host, "rimtstfpas.rimowa.com") || 										// RITM0026862
		/* END RIMOWA */					
		
		/* Royal Van Lent */				
        dnsDomainIs(host, "lentyard.local") || 									// RVL internal domain RITM0084437
        shExpMatch(host, "plm.feadship.nl") || 			                        // RVL internal domain RITM0091566
        shExpMatch(host, "fsaccweb.devooglt.feadship.nl") ||                    // RVL internal domain RITM0091566
        /* END Royal Van Lent */	
					
		/* Rossimoda */				
		dnsDomainIs(host, "qlik.rossimoda.com") || 											// Rossimoda internal resource
		dnsDomainIs(host, ".sedecentrale.rossimoda.com") || 								// Rossimoda internal Domain
		/* END Rossimoda */																	
					
		/* SEPHORA APAC */				
		dnsDomainIs(host, ".wocca.sephora.cn") ||											// REQ0029154 
		dnsDomainIs(host, ".aicca-lan.sephora.cn") ||				    					// REQ0029154 
		dnsDomainIs(host, ".uataicca-lan.sephora.cn") ||									// REQ0029154 
		dnsDomainIs(host, ".dianping.com") ||												// INC0034598 
		shExpMatch(host, "prod-web-dot-sfmc-edenred-burn.df.r.appspot.com") ||				// RITM0040277
		dnsDomainIs(host, ".oss-ap-southeast-1.aliyuncs.com") ||	            			// RITM0049993
        shExpMatch(host, "sephora-sg.domo.com") ||	                            			// RITM0050140
        dnsDomainIs(host, "allmyit.sephora.asia") ||			                            // RITM0061171
        dnsDomainIs(host, "njm.kpdn.gov.my") ||	            			                    // RITM0090491
        dnsDomainIs(host, "sephora-sg-asia.domo.com") ||                       //RITM0090666

		/* END SEPHORA APAC */				
					
		/* SEPHORA EME */				
		dnsDomainIs(host, ".adam.net") ||													// Sephora internal domain
		dnsDomainIs(host, "sephora-inside.fr") ||											// RITM0049765 - Sephora internal resource
		dnsDomainIs(host, "eservices.ejar.sa") ||                                           // RITM0072829
		dnsDomainIs(host, "ejar.sa") ||                                                     // RITM0073505
		dnsDomainIs(host, "fesurvey.stats.gov.sa") ||                                       // RITM0076416
		dnsDomainIs(host, "cc-specto.echoccs.com") ||                                       // RITM0080273
		/* END SEPHORA EME */			
				
		/* SEPHORA US */			
		dnsDomainIs(host, "dashboard.braze.com") ||											// RITM0036263
		dnsDomainIs(host, "dashboard-01.braze.com") ||										// RITM0036264
		shExpMatch(host, "hasm-qa.sephora.com") ||											// RITM0036265
		dnsDomainIs(host, ".internalsephora.com") ||										// Sephora US internal domain
		dnsDomainIs(host, ".sephoraus.com") ||												// Sephora US internal domain
		dnsDomainIs(host, "sepscpotst2.jdadelivers.com") ||									// RITM0037135
		dnsDomainIs(host, "sephorausa.custhelp.com") ||                        				// RITM0037020
        dnsDomainIs(host, "sephora.secure.force.com") ||                        			// RITM0037736
		shExpMatch(host, "atg11-m-ebf.sephora.com") ||                          			// RITM0037764
		shExpMatch(host, "dev.brandhub.sephora.com") ||                         			// RITM0037764
		shExpMatch(host, "dev.identity.brandhub.sephora.com") ||                			// RITM0037764
		shExpMatch(host, "gratis-qa.sites.sephora.com") ||                      			// RITM0037764
		shExpMatch(host, "hasm-perf.sephora.com") ||                            			// RITM0037764
		shExpMatch(host, "helpme-qa.sephora.com") ||                            			// RITM0037764
	//	dnsDomainIs(host, "sephora-qa-auth.yantriks.com") ||                  				// RITM0038128
    //  dnsDomainIs(host, "sephora-qa-inventory-dashboard.yantriks.com") ||   				// RITM0038128
	//	dnsDomainIs(host, "sephora-prod-auth.yantriks.com") ||								// RITM0037941
    //  dnsDomainIs(host, "sephora-prod-inventory-dashboard.yantriks.com") ||				// RITM0037941
        dnsDomainIs(host, "passion-azre1-dev01.sephora.com") ||	                			// RITM0039836
        dnsDomainIs(host, "passion-azre1-api-dev01.sephora.com") ||	            			// RITM0039836
        dnsDomainIs(host, "sephora.jamfcloud.com") ||                           			// RITM0039129
        dnsDomainIs(host, "sephora.riversand.com") ||                           			// RITM0046733
        dnsDomainIs(host, "azre1-dev02-csc.internal.sephora.com") ||            			// RITM0046948
        shExpMatch(host, "sephoraus.okta.com") ||                               			// RITM0047516
		dnsDomainIs(host, "ok12static.oktacdn.com") ||        				    			// INC0057864
		dnsDomainIs(host, "sephoraus.oktapreview.com") || 					    			// RITM0059551
		dnsDomainIs(host, "sitetraining.sephora.com")  ||                                  // RITM0062465
		dnsDomainIs(host, "braze.com")          ||                                           // RITM0064608
		dnsDomainIs(host, "transfer.inktel.com")     		    ||                         // RITM0065047
		dnsDomainIs(host, "eservices.oaed.gr")     		    ||                         // RITM0071653
		dnsDomainIs(host, "aek.oaed.gr")     		    ||                              // RITM0071653
		/* END SEPHORA US */	
		
		/* StellaMcCartney */				
		dnsDomainIs(host, ".stellamccartney.com") ||										// SMC internal domain
		dnsDomainIs(host, ".stellamccartney.dom") ||										// SMC internal domain
		/* END StellaMcCartney */
			
		/* Tiffany */			
		dnsDomainIs(host, ".occ.bt.com") ||													// Tiffany domain going through BT tunnels
		dnsDomainIs(host, ".tif.ccc.bt.com") ||												// Tiffany domain going through BT tunnels
		shExpMatch(host, "oa1.cloud.ccc.bt.com") ||                     	 				// Tiffany host going through BT tunnels
		shExpMatch(host, "hcs-cucdm2-wp1.vmphcs.bt.net") ||                     			// Tiffany host going through BT tunnels
	//	dnsDomainIs(host, "tif.fni-stl.com") ||                      						// INC0040339 
		shExpMatch(host, "www.ehr-dr.jp") ||												// Tiffany HR in Japan
		dnsDomainIs(host, "eastpondholdings.com") ||										// Tiffany internal domain
		dnsDomainIs(host, ".jdadelivers.com") ||                      					
		dnsDomainIs(host, "iridesse.com") ||												// Tiffany internal domain
		dnsDomainIs(host, "laureltondiamonds.com") ||										// Tiffany internal domain
		dnsDomainIs(host, "laureltongems.com") ||											// Tiffany internal domain
		shExpMatch(host, "tiffin02a.tiffany.com") ||			
		shExpMatch(host, "tiffin02b.tiffany.com") ||
		shExpMatch(host, "tiffin01a.tiffany.com") ||
		shExpMatch(host, "tiffin01b.tiffany.com") ||
		shExpMatch(host, "tiffin03a.tiffany.com") ||
		shExpMatch(host, "tiffin03b.tiffany.com") ||
		shExpMatch(host, "www.qa3.tiffany.com") ||
		shExpMatch(host, "www.qa2.tiffany.ca") ||
		shExpMatch(host, "www.qa3.tiffany.ca") ||
		shExpMatch(host, "www.qa1.tiffany.ca") ||
		shExpMatch(host, "www.qa2.fr.tiffany.ca") ||
		shExpMatch(host, "www.qa3.fr.tiffany.ca") ||
		shExpMatch(host, "www.qa1.fr.tiffany.ca") ||
		shExpMatch(host, "www.qa2.tiffany.com.mx") ||
		shExpMatch(host, "www.qa3.tiffany.com.mx") ||
		shExpMatch(host, "www.qa1.tiffany.com.mx") ||
		shExpMatch(host, "www.qa2.tiffany.com.br") ||
		shExpMatch(host, "www.qa3.tiffany.com.br") ||
		shExpMatch(host, "www.qa1.tiffany.com.br") ||
		shExpMatch(host, "www.qa2.tiffany.co.uk") ||
		shExpMatch(host, "www.qa3.tiffany.co.uk") ||
		shExpMatch(host, "www.qa1.tiffany.co.uk") ||
		shExpMatch(host, "www.qa2.tiffany.at") ||
		shExpMatch(host, "www.qa3.tiffany.at") ||
		shExpMatch(host, "www.qa1.tiffany.at") ||
		shExpMatch(host, "www.qa2.be.tiffany.com") ||
		shExpMatch(host, "www.qa3.be.tiffany.com") ||
		shExpMatch(host, "www.qa1.be.tiffany.com") ||
		shExpMatch(host, "www.qa2.tiffany.fr") ||
		shExpMatch(host, "www.qa3.tiffany.fr") ||
		shExpMatch(host, "www.qa1.tiffany.fr") ||
		shExpMatch(host, "www.qa2.tiffany.de") ||
		shExpMatch(host, "www.qa3.tiffany.de") ||
		shExpMatch(host, "www.qa1.tiffany.de") ||
		shExpMatch(host, "www.qa2.tiffany.ie") ||
		shExpMatch(host, "www.qa3.tiffany.ie") ||
		shExpMatch(host, "www.qa1.tiffany.ie") ||
		shExpMatch(host, "www.qa2.tiffany.it") ||
		shExpMatch(host, "www.qa3.tiffany.it") ||
		shExpMatch(host, "www.qa1.tiffany.it") ||
		shExpMatch(host, "www.qa2.nl.tiffany.com") ||
		shExpMatch(host, "www.qa3.nl.tiffany.com") ||
		shExpMatch(host, "www.qa1.nl.tiffany.com") ||
		shExpMatch(host, "www.qa2.tiffany.es") ||
		shExpMatch(host, "www.qa3.tiffany.es") ||
		shExpMatch(host, "www.qa1.tiffany.es") ||
		shExpMatch(host, "www.qa2.tiffany.ru") ||
		shExpMatch(host, "www.qa3.tiffany.ru") ||
		shExpMatch(host, "www.qa1.tiffany.ru") ||
		shExpMatch(host, "www.qa2.tiffany.co.jp") ||
		shExpMatch(host, "www.qa3.tiffany.co.jp") ||
		shExpMatch(host, "www.qa1.tiffany.co.jp") ||
		shExpMatch(host, "www.qa2.tiffany.cn") ||
		shExpMatch(host, "www.qa3.tiffany.cn") ||
		shExpMatch(host, "www.qa1.tiffany.cn") ||
		shExpMatch(host, "www.qa2.zh.tiffany.com") ||
		shExpMatch(host, "www.qa3.zh.tiffany.com") ||
		shExpMatch(host, "www.qa1.zh.tiffany.com") ||
		shExpMatch(host, "www.qa2.tiffany.kr") ||
		shExpMatch(host, "www.qa3.tiffany.kr") ||
		shExpMatch(host, "www.qa1.tiffany.kr") ||
		shExpMatch(host, "www.qa2.tiffany.com.au") ||
		shExpMatch(host, "www.qa3.tiffany.com.au") ||
		shExpMatch(host, "www.qa1.tiffany.com.au") ||
		shExpMatch(host, "www.qa1.tiffany.com.my") ||
		shExpMatch(host, "www.qa1.tiffany.com.sg") ||
		shExpMatch(host, "www.qa2.international.tiffany.com") ||
		shExpMatch(host, "www.qa3.international.tiffany.com") ||
		shExpMatch(host, "www.qa1.international.tiffany.com") ||
		shExpMatch(host, "www.qa2.estore-tco.com") ||
		shExpMatch(host, "www.qa3.estore-tco.com") ||
		shExpMatch(host, "www.qa1.estore-tco.com") ||
		shExpMatch(host, "www.qa2.estore-tco.jp") ||
		shExpMatch(host, "www.qa3.estore-tco.jp") ||
		shExpMatch(host, "www.qa1.estore-tco.jp") ||
		shExpMatch(host, "www.qa2.salesservice.tiffany.com") ||
		shExpMatch(host, "www.qa3.salesservice.tiffany.com") ||
		shExpMatch(host, "www.qa1.salesservice.tiffany.com") ||
		shExpMatch(host, "www.ps.tiffanyandcofoundation.org") ||
        shExpMatch(host, "www.qaperf.tiffanyandcofoundation.org") ||
		shExpMatch(host, "www.qa1.tiffanyandcofoundation.org") ||
        shExpMatch(host, "www.qa2.tiffanyandcofoundation.org") ||
        shExpMatch(host, "www.qa3.tiffanyandcofoundation.org") ||
		dnsDomainIs(host, "nsw.gov.kh") ||		//RITM0084940
		dnsDomainIs(host, "apps.nsw.gov.kh") ||		//RITM0084940
		dnsDomainIs(host, "customs.gov.kh") ||		//RITM0084940
		dnsDomainIs(host, "owp.tax.gov.kh") ||		//RITM0084940
		dnsDomainIs(host, "www.nssf.gov.kh") ||		//RITM0084940
		dnsDomainIs(host, "lacms.mlvt.gov.kh") ||		//RITM0084940
		dnsDomainIs(host, "fwcms.mlvt.gov.kh") ||		//RITM0084940
		dnsDomainIs(host, "sicms.mlvt.gov.kh") ||		//RITM0084940
		dnsDomainIs(host, ".gov.vn") || //RITM0085739
		shExpMatch(host, "www.qa2.tiffanytrade.com") ||
		shExpMatch(host, "www.qa3.tiffanytrade.com") ||
		shExpMatch(host, "www.qa1.tiffanytrade.com") ||
		shExpMatch(host, "www.qa2.tiffanytrade.jp ") ||
		shExpMatch(host, "www.qa3.tiffanytrade.jp ") ||
		shExpMatch(host, "www.qa1.tiffanytrade.jp ") ||	
		shExpMatch(host, "internal.tiffanytrade.com") ||									// Tiffany internal resource
        shExpMatch(host, "tiffanytrade.com") ||							    				// Tiffany IP whitelist
		shExpMatch(host, "media.tiffany.com") ||			
		shExpMatch(host, "www.qaperf.tiffany.com") ||			
		shExpMatch(host, "www.ps.tiffany.com") ||			
		dnsDomainIs(host, "backend.tiffany.cn") ||											// Source IP filtering
		dnsDomainIs(host, "ebusiness.tiffany.cn") ||										// Tiffany internal domain
		dnsDomainIs(host, "tiffco.net") ||													// Tiffany internal domain
		/* END Tiffany */			
					
		/* W&J */			
		dnsDomainIs(host, "ddc.hublot.cn") ||                   							// RITM0029105
		dnsDomainIs(host, "oa.lvmhwatchjewelry.com.cn") ||     		 						// RITM0029105
		dnsDomainIs(host, "merchantservice.icbc.com.cn") ||    								// CHG0039399
		dnsDomainIs(host, "itservice.lvmhwatchjewelry.com.cn") ||    		    			// RITM0049556
		dnsDomainIs(host, "vps29w19.bellerage.com")  		||								// RITM0057214
	    dnsDomainIs(host, "ip011.bellerage.com")  	||		                    			// RITM0057214
	    dnsDomainIs(host, "fre-fec-prd-01-aci-registry.cn-shanghai.cr.aliyuncs.com")  	||		                    // RITM0079129
	    dnsDomainIs(host, "fre-fec-prd-01-aci-registry-vpc.cn-shanghai.cr.aliyuncs.com")  	||		                // RITM0079129
		/* END W&J */			
					
		/* ZENITH */			
		shExpMatch(host, "zenith.easydocmaker.ch") || 										// INC0026028 
		dnsDomainIs(host, ".cloud.keyshot.com") || 											// CHG0038055
		dnsDomainIs(host, ".esupport.proconcept.ch") || 									// INC0025439
		dnsDomainIs(host, "customerservice.zenith-watches.com")  							// INC0026879
		/* END ZENITH */
		)
	return "DIRECT";
		
	/* Should not be shared - To review */
		/* Specifique Holding */ 
	if 	(
		(isInNet(User_Lan_IP, "10.106.0.0", "255.255.0.0")
		)
		&&
		(																  
		dnsDomainIs(host, ".salesforceliveagent.com") || 									// RITM0017156 - WhiteListing Public IP / performance related ?
		dnsDomainIs(host, ".salesforce.com")  												// RITM0017156 - WhiteListing Public IP / performance related ?
		)			
		)			
	return "DIRECT";			
		/* END Specifique Holding */			
						
			
	/* Redirection to Beijing as latency issue from Hong Kong III */
     if (
        (
        (isInNet(User_Lan_IP, "10.179.76.0", "255.255.252.0"))||
        (isInNet(User_Lan_IP, "10.179.80.0", "255.255.252.0"))||
        (isInNet(User_Lan_IP, "10.179.84.0", "255.255.252.0"))
        )
        &&
        (
        dnsDomainIs(host, ".nmpa.gov.cn") // INC0037895
        )
        )
    return "PROXY bjs1.sme.zscloud.net:80; DIRECT";
    
    /* INC0059075 - Bypass sephora.portal.eu for Sephora Wireless Network  */
	if 	(
		(isInNet(User_Lan_IP, "10.186.82.0", "255.255.255.0")
		)
		&&
		(
		dnsDomainIs(host, "portal.sephora.eu") 
		)
		)
	return "DIRECT";
		/* INC0059075 - Bypass sephora.portal.eu for Sephora Wireless Network   */
		


	/********************************************/
	/*											*/
	/* 		Internal rerouting to PZEN  		*/
	/*											*/
	/********************************************/
	
	/* Rerouting Okta to PZEN to leverage DSSO */
	if (
		(InternalNetwork == "TRUE") 
		&&
		(
		/* Rerouting Okta to PZEN to leverage DSSO */
		shExpMatch(host, "okta.lvmh.com") ||
		dnsDomainIs(host, ".okta.com") ||
		dnsDomainIs(host, ".oktacdn.com") ||
		shExpMatch(host, "portal.sephora.eu") ||											// Sephora Okta
        shExpMatch(host, "sephora.okta-emea.com") 	||										// Sephora Okta
        dnsDomainIs(host, "okta-lab.lvmh.com") ||                           				// RITM0053477
        dnsDomainIs(host, ".oktapreview.com")  ||                             				// RITM0053477
        shExpMatch(host, "sephora-admin.okta-emea.com")                                     // RITM0077049
		)			
		)			
	return proxy_pzen;
	/* END Rerouting Okta to PZEN to leverage DSSO */
	
	
	
	/* Redirection to PZEN subcloud */
	if (
		(InternalNetwork == "TRUE") 
		&&
		(
		dnsDomainIs(host, ".sephora-dcm.adobecqms.net") ||									// RITM0049765
		dnsDomainIs(host, "dsb-sephora.allshare-scenario.fr") ||							// RITM0049765
		shExpMatch(host, "s4a-happy-xl-e2e.ew.r.appspot.com") ||							// RITM0049765
		shExpMatch(host, "s4a-happy-xl-uat.ew.r.appspot.com") ||							// RITM0049765
		shExpMatch(host, "s4a-happy-xl-dev.ew.r.appspot.com") ||							// RITM0049765
		shExpMatch(host, "s4a-happy-xl-prd.ew.r.appspot.com") ||							// RITM0049765
		dnsDomainIs(host, ".azuredatabricks.net") ||           			    				// RITM0037021
		dnsDomainIs(host, "ezlmappdc1f.adp.com") ||											// STB
		shExpMatch(host, "tiffany.billingit.com") ||										// Tiffany 
		dnsDomainIs(host, ".cybersource.com") ||											// RITM0037268
		dnsDomainIs(host, ".easypics.fr") ||												// RITM0049765
		shExpMatch(host, "www.ehr-dr.jp") ||												// Tiffany HR in Japan
		dnsDomainIs(host, "ekahau.cloud") ||			
		dnsDomainIs(host, "workforceportal.elabor.com") ||									
		dnsDomainIs(host, "beautynet.lightning.force.com") ||								// RITM0049765
		dnsDomainIs(host, "sephora-prd.legisway.com") ||									// RITM0049765
		dnsDomainIs(host, "bo-prod.lesechos.fr") || 										// RITM0037145
		shExpMatch(host, "bridger.lexisnexis.com") || 										
		shExpMatch(host, "bridgerstaging.lexisnexis.com") || 				
		dnsDomainIs(host, "riskmanagement.lexisnexis.com")  ||                  			// RITM0045405
        dnsDomainIs(host, "riskmanagement.lexisnexisrisk.com") ||               			// RITM0045405		
		dnsDomainIs(host, "www.paypal.com") ||			
		dnsDomainIs(host, "diams.proximy.net") ||                           				// RITM0036621 Migration Proximy 
		dnsDomainIs(host, "pevp.proximy.net") ||                            				// RITM0036621 Migration Proximy
		dnsDomainIs(host, "ba-app.sephora.sg") ||            			
		shExpMatch(host, "www.mdtc-rec.com") ||                                 			// RITM0049765
		shExpMatch(host, "sephora.oxiwork.com") ||											// RITM0049765
        dnsDomainIs(host, ".custhelp.com") ||        	            						// RITM0038269
		dnsDomainIs(host, ".ultipro.com") ||												// INC0022390 - PVIS US (Direct - Equipments incompatible with Zscaler)
		dnsDomainIs(host, ".yantriks.com") ||												// RITM0037941
		dnsDomainIs(host, "dataiku.gcp.data.sephora-asia.net") ||							// RITM0038978
		dnsDomainIs(host, ".fedex.com")	 ||									    			// RITM0038494
		dnsDomainIs(host, "fred.legisway.com")	 ||							    			// RITM0039875
		dnsDomainIs(host, "us-sandbox2-live.inside-graph.com")	||			    			// RITM0039206
	    dnsDomainIs(host, "sephora-apac.prod.plan.relexsolutions.com")	||   				// RITM0040454
	    dnsDomainIs(host, "sephora-apac.test.plan.relexsolutions.com")	||	    			// RITM0040243
		dnsDomainIs(host, "sephora-europe-test.relexsolutions.com") ||						// RITM0049765
		dnsDomainIs(host, "sephora-apac-test.relexsolutions.com") ||						// RITM0049765
		dnsDomainIs(host, "sephora-europe.test.plan.relexsolutions.com") ||					// RITM0049765
		dnsDomainIs(host, "sephora-europe.prod.plan.relexsolutions.com") ||					// RITM0049765
		dnsDomainIs(host, "sephora-latam.prod.plan.relexsolutions.com") ||					// RITM0049765
		dnsDomainIs(host, "sephora-latam.test.plan.relexsolutions.com") ||					// RITM0049765									
		dnsDomainIs(host, "www.sephora-intelligence.com") ||								// RITM0049765
		shExpMatch(host, "mysephoracareer.sephora.eu") ||									// RITM0049765
		shExpMatch(host, "sephora-jira.ttpsc.net") ||										// RITM0049765
		shExpMatch(host, "sephora-jira-test.ttpsc.net") ||									// RITM0049765
		dnsDomainIs(host, ".akbank.com.tr")	||												// RITM0039191
		dnsDomainIs(host, "genuinopuntozero.it")	||										// RITM0042644
		shExpMatch(host, "xapps60.inktel.com")	||							    			// RITM0043125
		dnsDomainIs(host, "api-gateway-x60.inktel.com")  ||                     			// RITM0043489
		dnsDomainIs(host, "lesechosv5.legisway.com")  ||                        			// RITM0043719
		dnsDomainIs(host, "sidetrade.net") ||                                   			// RITM0043775
		dnsDomainIs(host, "scheduler.3vfinance.org") ||                         			// RITM0042297
		dnsDomainIs(host, "my.101domain.com")       ||                          			// RITM0044676
		dnsDomainIs(host, "lvmh-oie1.oktapreview.com")  ||                      			// RITM0044663
		dnsDomainIs(host, ".gcp-int.lvmh.com")  ||                              			// RITM0045399
		dnsDomainIs(host, ".gcp-sta.lvmh.com")  ||                              			// RITM0056168																				
        dnsDomainIs(host, ".gcp.lvmh.com")      ||                              			// RITM0045399
		dnsDomainIs(host, ".aly-int.lvmh.cn")   ||											// RITM0058784
        dnsDomainIs(host, ".aly-sta.lvmh.cn")   ||											// RITM0058784
        dnsDomainIs(host, ".aly.lvmh.cn")       ||											// RITM0058784
        dnsDomainIs(host, "pp-web-files-org.lvmh.com") || 						            // RITM0065000
        dnsDomainIs(host, "web-files-org.lvmh.com")	   || 						            // RITM0065000
        dnsDomainIs(host, "pp-magellan-fun-org.lvmh.com")	   || 						    // RITM0085376
        dnsDomainIs(host, "pp-magellan-fun.lvmh.com")	   || 					 	        // RITM0085376
        dnsDomainIs(host, "magellan-fun-org.lvmh.com")	   || 						        // RITM0089697
        dnsDomainIs(host, "magellan-fun.lvmh.com")	       ||					 	        // RITM0089697
        dnsDomainIs(host, "tclearn.aptilink.com")||                             			// RITM0045438																												
        dnsDomainIs(host, "test-www.boursier.com")         ||                   			// RITM0045405
        dnsDomainIs(host, "bdadatalakedevadls1.blob.core.windows.net") || 					// RITM0045612
        dnsDomainIs(host, "bdadatalakedevadls2.blob.core.windows.net") || 					// RITM0045612
        dnsDomainIs(host, "bdadatalakedevadls3.blob.core.windows.net") ||					// RITM0045612
        dnsDomainIs(host, "bdadatalakeprdadls1.blob.core.windows.net") ||					// RITM0045612
        dnsDomainIs(host, "bdadatalakeprdadls2.blob.core.windows.net") ||					// RITM0045612
        dnsDomainIs(host, "bdadatalakeqaadls1.blob.core.windows.net") ||					// RITM0045612
        dnsDomainIs(host, "bbdadatocreativedevst1.blob.core.windows.net") ||				// RITM0045612
        dnsDomainIs(host, "bdadatocreativeprdst1.blob.core.windows.net") ||					// RITM0045612
        dnsDomainIs(host, "bdadatocreativeqast1.blob.core.windows.net") ||					// RITM0045612
        dnsDomainIs(host, "bdadatodevst1.blob.core.windows.net") ||							// RITM0045612
        dnsDomainIs(host, "bdadatoprdst1.blob.core.windows.net") ||							// RITM0045612
        dnsDomainIs(host, "bdadatoprdst1.blob.core.windows.net") ||							// RITM0045612
        dnsDomainIs(host, "bdadatalakedevadls1.dfs.core.windows.net") ||					// RITM0045612
        dnsDomainIs(host, "bdadatalakedevadls2.dfs.core.windows.net") ||					// RITM0045612
        dnsDomainIs(host, "bdadatalakedevadls3.dfs.core.windows.net") || 					// RITM0045612
        dnsDomainIs(host, "bdadatalakeprdadls1.dfs.core.windows.net") || 					// RITM0045612
        dnsDomainIs(host, "bdadatalakeprdadls2.dfs.core.windows.net") ||					// RITM0045612
        dnsDomainIs(host, "bdadatalakeqaadls1.dfs.core.windows.net") ||						// RITM0045612
        dnsDomainIs(host, "bdadatocreativedevst1.dfs.core.windows.net") ||					// RITM0045612
        dnsDomainIs(host, "bdadatocreativeprdst1.dfs.core.windows.net") ||					// RITM0045612
        dnsDomainIs(host, "bdadatocreativeqast1.dfs.core.windows.net") ||					// RITM0045612
        dnsDomainIs(host, "bdadatodevst1.dfs.core.windows.net") || 							// RITM0045612
        dnsDomainIs(host, "bdadatoprdst1.dfs.core.windows.net") || 							// RITM0045612
        dnsDomainIs(host, "bdadatoqast1.dfs.core.windows.net") ||							// RITM0045612
        dnsDomainIs(host, "bda-serversql-dev.database.windows.net") ||						// RITM0045612
        dnsDomainIs(host, "bda-serversql-qa.database.windows.net") ||						// RITM0045612
        dnsDomainIs(host, "bda-serversql-prd.database.windows.net") ||						// RITM0045612
        dnsDomainIs(host, "aeun-zen-pbi-dev-01-synapse.dev.azuresynapse.net")  ||           // RITM0046022
        dnsDomainIs(host, "aeun-zen-pbi-dev-01-synapse-ondemand.sql.azuresynapse.net")  ||  // RITM0046022
        dnsDomainIs(host, "aeun-zen-pbi-prd-01-synapse.dev.azuresynapse.net")  ||           // RITM0046022
        dnsDomainIs(host, "aeun-zen-pbi-prd-01-synapse-ondemand.sql.azuresynapse.net") ||   // RITM0046022
        dnsDomainIs(host, "nbp.sephora-asia.com")               ||                          // RITM0046843
        dnsDomainIs(host, "www.qa1.tiffany.com")                ||                          // RITM0047747
        dnsDomainIs(host, "www.qa2.tiffany.com")                ||                          // RITM0047747
        dnsDomainIs(host, "azre1-dev2.sephora.com")             ||                          // RITM0048043
        dnsDomainIs(host, "dev2.sephora.com")                   ||                          // RITM0048046
        dnsDomainIs(host, "echos-v2-bo.sdv.fr")                 ||                          // RITM0048110
        dnsDomainIs(host, "echos-v2preprod-bo.sdv.fr")          ||                          // RITM0048110
        dnsDomainIs(host, "45.147.208.12")                      ||                          // RITM0048725
        shExpMatch(host, "34.79.250.2")                         ||                          // RITM0050023
        shExpMatch(host, "34.22.245.255")                       ||                          // RITM0050144
        dnsDomainIs(host, ".eastus.azmk8s.io")  ||                                          // RITM0050476
        dnsDomainIs(host, ".westus.azmk8s.io")  ||                                          // RITM0050476
        dnsDomainIs(host, "devops.chaumet.com") ||                                          // RITM0051448
        dnsDomainIs(host, "csctraining.sephoraus.com") ||                                   // RITM0052231
        dnsDomainIs(host, "tech.salondesentrepreneurs.com") ||                              // RITM0052178
        dnsDomainIs(host, "sde.salondesentrepreneurs.com")  ||                              // RITM0052178
        dnsDomainIs(host, "echos-sde1.sdv.fr")             ||                               // RITM0052178
        dnsDomainIs(host, "sephora-prod-inventory-dashboard.yantriks.com")  ||              // RITM0052793
        dnsDomainIs(host, "oms.fgcndigital.com") ||                							// RITM0052996
        dnsDomainIs(host, "mgrbeco01mstrh0og5inte.dxcloud.episerver.net")  ||          		// RITM0053445
        dnsDomainIs(host, "mgrbeco01mstrh0og5prep.dxcloud.episerver.net")  ||          		// RITM0053445
        dnsDomainIs(host, "zendesk.luxola.com")     ||         								// RITM0053680
        dnsDomainIs(host, "tif.fni-stl.com")        ||                                      // RITM0054319 																		 
        shExpMatch(host, "81.12.128.94")     ||                                             // RITM0054462
		dnsDomainIs(host, "sephora-biz.cashstar.com")      ||                               // RITM0055202
        dnsDomainIs(host, "sephoraca-biz.cashstar.com")      ||                             // RITM0055202
        dnsDomainIs(host, "sephoraca-biz.semi.cashstar.com")      ||                        // RITM0055202
        dnsDomainIs(host, "faceplate-management.cashstar.com")      ||                      // RITM0055202
        dnsDomainIs(host, "manager.cashstar.com")      ||                                   // RITM0055202
        dnsDomainIs(host, "sephora.semi.cashstar.com")      ||                              // RITM0055202
        dnsDomainIs(host, "sephoraca.semi.cashstar.com")    ||                              // RITM0055202
        dnsDomainIs(host, "diorazure-paph.christiandior.com")   ||                          // RITM0058291
        dnsDomainIs(host, "diorazure-papf.christiandior.com")   ||                          // RITM0058291
        dnsDomainIs(host, "diorazure-hc.christiandior.com")     ||                          // RITM0058291
        shExpMatch(url, "sephora.com/mirror")  ||								            // RITM0059411
        shExpMatch(url, "sephora.com/mirror/*") ||								            // RITM0059411
        shExpMatch(url, "sephora.com/c3mirror") ||								            // RITM0059411
        shExpMatch(url, "sephora.com/c3mirror/*") ||								        // RITM0059411
        shExpMatch(host, "cms-medusa.tv.sfr.net") ||  							  			// RITM0059495
        shExpMatch(host, "dld.mykds.com") ||                                                // RITM0060256
        shExpMatch(host, "prdld.mykds.com")    ||                                           // RITM0060278
        dnsDomainIs(host, "sepscpotst2.jdadelivers.com") ||		                            // RITM0061728
        dnsDomainIs(host, "secretshare.celine.net")   ||				                    // RITM0061898
        dnsDomainIs(host, "subscriber-area.service.dev.gcp.eilep.io") ||				    // RITM0062047
        dnsDomainIs(host, "crm.annonces-legales.fr") 			||	                        // RITM0062481
        dnsDomainIs(host, "sephora-europe-test.relexsolutions.com") 	||			        // RITM0062496
        dnsDomainIs(host, "sephora-europe.relexsolutions.com") 	||			                // RITM0062496
        dnsDomainIs(host, "sephora-apac-test.relexsolutions.com") 	||			            // RITM0062496
        dnsDomainIs(host, "sephora-dev.test.plan.relexsolutions.com") 	||			        // RITM0062496
        dnsDomainIs(host, "sephora-europe.prod.plan.relexsolutions.com") 	||			    // RITM0062496
        dnsDomainIs(host, "sephora-europe.test.plan.relexsolutions.com") 	||			    // RITM0062496
        dnsDomainIs(host, "sephora-apac.test.plan.relexsolutions.com") 	||			        // RITM0062496
        dnsDomainIs(host, "sephora-apac.relexsolutions.com") 	||			                // RITM0062496
        dnsDomainIs(host, "sephora-core-model.prod.plan.relexsolutions.com") 	||			// RITM0062496
        dnsDomainIs(host, "sephora-apac.prod.plan.relexsolutions.com") 	||			        // RITM0062496
        dnsDomainIs(host, "identity.prod-eu.prod.cc.relexsolutions.com") 	||			    // RITM0062496
        dnsDomainIs(host, "sephora-latam.prod.plan.relexsolutions.com") 	||			    // RITM0062496
        dnsDomainIs(host, "sephora-latam.test.plan.relexsolutions.com") 	||			    // RITM0062496
        dnsDomainIs(host, "auto.fgcndigital.com") 				            ||              // RITM0062517
        dnsDomainIs(host, "lecercle.groupelesechos.fr")     		        ||              // RITM0063779
        dnsDomainIs(host, "sft.kelmarassoc.com")     		                ||              // RITM0064631
        dnsDomainIs(host, "admin.profile.parismatch.com/login")     		||              // RITM0064892
        dnsDomainIs(host, "jenkinsqa.leparisien.fr")                        ||              // RITM0065944
        dnsDomainIs(host, "sergit2.leparisien.fr")                          ||              // RITM0065944
        dnsDomainIs(host, "www.co.lavoro.gov.it/co/welcome.aspx")           ||              // RITM0066033
        dnsDomainIs(host, "satisfaction.sephora.eu")		    		    ||              // RITM0066317
        dnsDomainIs(host, "evisa.gov.kh")                                   ||              // RITM0067096
        dnsDomainIs(host, "nprd.private-digital.sephora.eu")                ||              // RITM0067209
        dnsDomainIs(host, "cms-nprd-gcp.sephora.eu")                        ||              // RITM0067209
        dnsDomainIs(host, ".boursier.com")                                  ||              // RITM0067209
        dnsDomainIs(host, "scp.q2cloud.net")  				                ||              // RITM0067366
        dnsDomainIs(host, "www.staging.parismatch.com")  				    ||              // RITM0067379
        dnsDomainIs(host, "login.sephora.com")  				            ||              // RITM0067765
        dnsDomainIs(host, "www.qa3.estore-tco.com")  				        ||              // RITM0067956
        dnsDomainIs(host, "myteamsrh-009.cegedim-srh.net")  				||              // RITM0068578
        dnsDomainIs(host, "odoo-preprod.annonces.lesechosleparisien.fr")  	||              // RITM0068755
        dnsDomainIs(host, "odoo-test.annonces.lesechosleparisien.fr")  	    ||              // RITM0068756
        dnsDomainIs(host, "odoo-qualif.annonces.lesechosleparisien.fr")  	||              // RITM0068757
        dnsDomainIs(host, "odoo.annonces.lesechosleparisien.fr")  	        ||              // RITM0068758
        dnsDomainIs(host, "sephorafr-mkt-stage10.campaign.adobe.com")  	    ||              // RITM0068981
        dnsDomainIs(host, "sephorafr-mkt-stage14.campaign.adobe.com")  	    ||              // RITM0068981
        dnsDomainIs(host, "sephorafr-mkt-stage18.campaign.adobe.com")  	    ||              // RITM0068981
        dnsDomainIs(host, "sephorafr-mkt-prod10.campaign.adobe.com")  	    ||              // RITM0068981
        dnsDomainIs(host, "experience.adobe.com")  	                        ||              // RITM0068981
        dnsDomainIs(host, "loropiana.zucchetti.com")                        ||              // RITM0069022
        dnsDomainIs(host, "portal.sephora.com")                             ||              // RITM0069277
        dnsDomainIs(host, "sephora-global.sephora.com")                     ||              // RITM0069278
        dnsDomainIs(host, "portal.sephora.fr")                              ||              // RITM0069310
        dnsDomainIs(host, "sephora-preprod.x27crm.com")                     ||              // RITM0069310
        dnsDomainIs(host, "sephora-mea-preprod.x27crm.com")                 ||              // RITM0069310
        dnsDomainIs(host, "sephora-rec-m.x27crm.com")                       ||              // RITM0069310
        dnsDomainIs(host, "qa.sephora.com")                                 ||              // RITM0069668
        dnsDomainIs(host, "qa2.sephora.com")                                ||              // RITM0069668
        dnsDomainIs(host, "qa3.sephora.com")                                ||              // RITM0069668
        dnsDomainIs(host, "qa4.sephora.com")                                ||              // RITM0069668
        dnsDomainIs(host, "qa5.sephora.com")                                ||              // RITM0069668
        dnsDomainIs(host, "qa11.sephora.com")                               ||              // RITM0069668
        dnsDomainIs(host, "atg11-ebf.sephora.com")                          ||              // RITM0069668
        dnsDomainIs(host, "perf1.sephora.com")                              ||              // RITM0069668
        dnsDomainIs(host, "api-qa.sephora.com")                             ||              // RITM0069668
        dnsDomainIs(host, "api-qa2.sephora.com")                            ||              // RITM0069668
        dnsDomainIs(host, "api-qa3.sephora.com")                            ||              // RITM0069668
        dnsDomainIs(host, "api-qa4.sephora.com")                            ||              // RITM0069668
        dnsDomainIs(host, "api-qa5.sephora.com")                            ||              // RITM0069668
        dnsDomainIs(host, "api-qa11.sephora.com")                           ||              // RITM0069668
        dnsDomainIs(host, "atg11-api-ebf.sephora.com")                      ||              // RITM0069668
        dnsDomainIs(host, "api-perf1.sephora.com")                          ||              // RITM0069668
        dnsDomainIs(host, "api-developer.sephora.com")                      ||              // RITM0069668
        dnsDomainIs(host, "m-qa.sephora.com")                               ||              // RITM0069668
        dnsDomainIs(host, "m-qa3.sephora.com")                              ||              // RITM0069668
        dnsDomainIs(host, "m-qa4.sephora.com")                              ||              // RITM0069668
        dnsDomainIs(host, "qa-api-developer.sephora.com")                   ||              // RITM0069668
        dnsDomainIs(host, "qa.brandhub.sephora.com")                        ||              // RITM0069668
        dnsDomainIs(host, "qa.identity.brandhub.sephora.com")               ||              // RITM0069668
        dnsDomainIs(host, "stage-api-developer.sephora.com")                ||              // RITM0069668
        dnsDomainIs(host, "extqa-api-developer.sephora.com")                ||              // RITM0069668
        dnsDomainIs(host, "stage-developer.sephora.com")                    ||              // RITM0069668
        dnsDomainIs(host, "hasm.sephora.com")                               ||              // RITM0069668
        dnsDomainIs(host, "sephora-mea-rec-m.x27crm.com")                   ||              // RITM0069384
        dnsDomainIs(host, "monitoring-sephora-rec.etocrm.fr")               ||              // RITM0069384
        dnsDomainIs(host, "sephora-ws-rec-m.etocrm.fr")                     ||              // RITM0069384
        dnsDomainIs(host, "monitoring-sephora-preprod.etocrm.fr")           ||              // RITM0069384
        dnsDomainIs(host, "sephora-ws-preprod.etocrm.fr")                   ||              // RITM0069384
        dnsDomainIs(host, "sephora.x27crm.com")                             ||              // RITM0069384
        dnsDomainIs(host, "sephora-mea.x27crm.com")                         ||              // RITM0069384
        dnsDomainIs(host, "monitoring-sephora.etocrm.fr")                   ||              // RITM0069384
        dnsDomainIs(host, "sephora-ws.etocrm.fr")                           ||              // RITM0069384
        shExpMatch(host, "api-preprod.axiocap.com/api/v1/swagger/")         ||              // RITM0068588
        dnsDomainIs(host, "es-cn-lbj3p0u0e000kizn3-kibana.cn-shanghai.elasticsearch.aliyuncs.com")           ||    // RITM0069485
        dnsDomainIs(host, "es-cn-36z3qcerb0002tehx-kibana.cn-shanghai.elasticsearch.aliyuncs.com")           ||    // RITM0069486
        dnsDomainIs(host, "lesechos-mkt-stage8.campaign.adobe.com")        ||               // RITM0069793
        dnsDomainIs(host, "admin.odella.fr")                               ||               // RITM0070161
        dnsDomainIs(host, "www2.buybox.net")                               ||               // RITM0070488
        dnsDomainIs(host, "lvmh.huilianyi.com")                            ||               // RITM0070320
        dnsDomainIs(host, "www.sephora.com")                               ||               // RITM0071382
        dnsDomainIs(host, "jira-stage.sephora.com.edgekey.net")            ||              // RITM0075249
        dnsDomainIs(host, "confluence-stage.sephora.com.edgekey.net")      ||              // RITM0075249
        dnsDomainIs(host, "confluence.sephora.com.edgekey.net")            ||              // RITM0075249
        dnsDomainIs(host, "jira.sephora.com.edgekey.net")                  ||              // RITM0075249
        dnsDomainIs(host, "jira-stage.sephora.com")                        ||              // RITM0075249
        dnsDomainIs(host, "confluence-stage.sephora.com")                  ||              // RITM0075249
        dnsDomainIs(host, "recovery.sephora.com")                          || // RITM0089717
        dnsDomainIs(host, "api-recovery.sephora.com")                      || // RITM0089717
        dnsDomainIs(host, "passion-azre1-recovery-prod-api-developer.sephora.com") || // RITM0089717
        dnsDomainIs(host, "passion-azre1-jerri-recovery.sephora.com")      || // RITM0089717
        dnsDomainIs(host, "passion-azre1-recovery.sephora.com")            || // RITM0089717
        dnsDomainIs(host, "passion-azre1-woody-recovery.sephora.com")      || // RITM0089717
        dnsDomainIs(host, "passion-azre1-es-recovery.sephora.com")         || // RITM0089717
        dnsDomainIs(host, "passion-azre1-jerri-catalog-recovery.sephora.com") || // RITM0089717
        dnsDomainIs(host, "passion-azre1-jerri-content-recovery.sephora.com") || // RITM0089717
        dnsDomainIs(host, "christiandior.lightning.force.com")              ||              // RITM0075505
        dnsDomainIs(host, "christiandior.my.salesforce.com")                ||              // RITM0075505
        dnsDomainIs(host, "www-admin.belmond.com")                         ||               // RITM0071528
        shExpMatch(host, "berluti.my.salesforce.com")                      ||               // RITM0073507
        dnsDomainIs(host, "berluti.my.salesforce.com")                     ||               // RITM0072595
        dnsDomainIs(host, ".1008e.mongodb.net")                            ||               // RITM0072736
        dnsDomainIs(host, ".kxylc.mongodb.net")                            ||               // RITM0072736
        dnsDomainIs(host, "www-staging.belmondpro.com")                    ||               // RITM0072940
        dnsDomainIs(host, "www-staging.belmond.com")                       ||               // RITM0072940
        dnsDomainIs(host, "www-preview-staging.belmond.com")               ||               // RITM0072940
        dnsDomainIs(host, "berluti.my.salesforce.com")                     ||               // RITM0073507
        dnsDomainIs(host, "dns-aks-container-dmz-hosting-weu-nonprd-63e4d079.hcp.westeurope.azmk8s.io")    ||         // RITM0073507
        dnsDomainIs(host, "dns-aks-container-dmz-hosting-weu-ppd-f257e5cb.hcp.westeurope.azmk8s.io")       ||         // RITM0073507
        dnsDomainIs(host, "dns-aks-container-dmz-hosting-weu-prd-da1e8faf.hcp.westeurope.azmk8s.io")       ||         // RITM0073507
        dnsDomainIs(host, "dns-aks-container-trust-hosting-weu-nonprd-3a883eaf.hcp.westeurope.azmk8s.io")  ||         // RITM0073507
        dnsDomainIs(host, "dns-aks-container-trust-hosting-weu-ppd-5c719a00.hcp.westeurope.azmk8s.io")     ||         // RITM0073507
        dnsDomainIs(host, "dns-aks-container-trust-hosting-weu-prd-f5212bc4.hcp.westeurope.azmk8s.io")     ||         // RITM0073507
        dnsDomainIs(host, "www-cm-staging.belmond.com")                     ||		        // RITM0073850
        dnsDomainIs(host, "www-dev.belmond.com")                            ||				// RITM0073850
        dnsDomainIs(host, "www-cm-dev.belmond.com")                         ||				// RITM0073850
        dnsDomainIs(host, "www-preview-dev.belmond.com")                    ||			    // RITM0073850 
        dnsDomainIs(host, "www-admin.belmondpro.com")                       ||			    // RITM0073850
        dnsDomainIs(host, "www-cm-staging.belmondpro.com")                  ||		        // RITM0073850
        dnsDomainIs(host, "www-preview-staging.belmondpro.com")             ||	            // RITM0073850
        dnsDomainIs(host, "www-dev.belmondpro.com")                         ||				// RITM0073850
        dnsDomainIs(host, "www-cm-dev.belmondpro.com")                      ||			    // RITM0073850
        dnsDomainIs(host, "www-preview-dev.belmondpro.com")                 ||		        // RITM0073850
        dnsDomainIs(host, "www-admin.thelalee.co.uk")                       ||			    // RITM0073850
        dnsDomainIs(host, "www-staging.thelalee.co.uk")                     ||			    // RITM0073850
        dnsDomainIs(host, "www-cm-staging.thelalee.co.uk")                  ||		        // RITM0073850
        dnsDomainIs(host, "www-preview-staging.thelalee.co.uk")             ||	            // RITM0073850
        dnsDomainIs(host, "www-dev.thelalee.co.uk")                         ||				// RITM0073850
        dnsDomainIs(host, "www-cm-dev.thelalee.co.uk")                      ||			    // RITM0073850
        dnsDomainIs(host, "www-preview-dev.thelalee.co.uk")                 ||		        // RITM0073850
        dnsDomainIs(host, "www-admin.21club.com")                           ||			    // RITM0073850
        dnsDomainIs(host, "www-staging.21club.com")                         ||				// RITM0073850
        dnsDomainIs(host, "www-cm-staging.21club.com")                      ||			    // RITM0073850
        dnsDomainIs(host, "www-preview-staging.21club.com")                 ||		        // RITM0073850
        dnsDomainIs(host, "www-dev.21club.com")                             ||				// RITM0073850
        dnsDomainIs(host, "www-cm-dev.21club.com")                          ||				// RITM0073850
        dnsDomainIs(host, "www-preview-dev.21club.com")                     ||    			// RITM0073850
        dnsDomainIs(host, "cloud.news.loropiana.com")                       ||    			// RITM0074067
        dnsDomainIs(host, "backoffice.buybox.net")                          ||              // RITM0074790  
        dnsDomainIs(host, "dev-sfcc-eu-api.christiandior.com")              ||              // RITM0075992
        dnsDomainIs(host, "development-eu01-christiandior.demandware.net")  ||              // RITM0075992
        dnsDomainIs(host, "sfcc-eu-api.christiandior.com")                  ||              // RITM0076029
        dnsDomainIs(host, "production-eu01-christiandior.demandware.net")   ||              // RITM0076029
        dnsDomainIs(host, "staging.historia.fr")                            ||              // RITM0076006
        dnsDomainIs(host, "preprod.historia.fr")                            ||              // RITM0076006
        dnsDomainIs(host, "test.historia.fr")                               ||              // RITM0076006
        dnsDomainIs(host, "preprod-test.historia.fr")                       ||              // RITM0076006
        dnsDomainIs(host, "stg-sfcc-eu-api.christiandior.com")              ||              // RITM0076268
        dnsDomainIs(host, "staging-eu01-christiandior.demandware.net")      ||              // RITM0076268
        dnsDomainIs(host, "berluti.printix.net")                            ||              // RITM0076561
        dnsDomainIs(host, "sephora.secretservercloud.com")                  ||              // RITM0076738
        dnsDomainIs(host, "kevtool.christiandior.com")                      ||              // RITM0076855
        dnsDomainIs(host, "dev-kevtool.christiandior.com")                  ||              // RITM0076855
        dnsDomainIs(host, "preview-prod.sephora.com")                       ||              // RITM0077051
        dnsDomainIs(host, "tif-poc-fzdvdjbnhxfgbca4.a02.azurefd.net")       ||              // RITM0077165
        dnsDomainIs(host, "vivatechnology.com")                             ||              // RITM0077318
        dnsDomainIs(host, "*sephora.cam")                                   ||              // RITM0077139
        shExpMatch(host, "*.historia.fr")                                   ||              // RITM0078510
        dnsDomainIs(host, "test.lesechos.fr")                               ||              // RITM0078655
        dnsDomainIs(host, "sastdtlddteuint.file.core.windows.net")          ||              // RITM0078655
        dnsDomainIs(host, "mulesoft-uat-int.lvmhwatchjewelry.com.cn")       ||              // RITM0078673
        dnsDomainIs(host, "388.taxroute.kpmg.com.tr")                       ||              // RITM0078786
        dnsDomainIs(host, "s-tctsv2.belmond.com")                           ||              // RITM0078785
        dnsDomainIs(host, "s-odltsv2-app02.belmond.com")                    ||              // RITM0078785
        dnsDomainIs(host, "www.rimowa.com")                                 ||              // RITM0073419
        dnsDomainIs(host, "we4.ondemand.esker.com")                         ||              // RITM0079205
        dnsDomainIs(host, "smartrh-berlu.cegedim-srh.net")                  ||              // RITM0079204
        dnsDomainIs(host, "lvmhfashion.service-now.com")                    ||              // RITM0079206
        dnsDomainIs(host, "authentication-prod.ar.indazn.com")              ||              // INC0217697
        dnsDomainIs(host, "www.concursolutions.com")                        ||              // RITM0079207
        dnsDomainIs(host, "s4a-hyperplan-dev.appspot.com")                  ||              // RITM0080878
        dnsDomainIs(host, "s4a-hyperplan-uat.appspot.com")                  ||              // RITM0080878
        dnsDomainIs(host, "s4a-hyperplan-prd.appspot.com")                  ||              // RITM0080878
        dnsDomainIs(host, "we4.ondemand.esker.com")                         ||              // RITM0081074
        dnsDomainIs(host, "www-us.api.concursolutions.com")                 ||              // RITM0081072
        dnsDomainIs(host, "federatedid-na1.services.adobe.com")             ||              // RITM0081073
        dnsDomainIs(host, "www.amazon.it")                                  ||              // RITM0081066
        dnsDomainIs(host, "37.18.43.94")                                    ||              // RITM0081108
        dnsDomainIs(host, "37.18.43.98")                                    ||              // RITM0081108
        dnsDomainIs(host, "www-bt-preview-staging.belmond.com")             ||              // RITM0083639
        dnsDomainIs(host, "sephora-biz.cashstar.com")                       ||              // RITM0084777
        dnsDomainIs(host, "api.eu.cast.ai")                                 ||              // RITM0083639
        dnsDomainIs(host, "us-docker.pkg.dev")                              ||              // RITM0083639
        dnsDomainIs(host, "asia-east1-docker.pkg.dev")                      ||              // RITM0083639
        dnsDomainIs(host, "gcr.io")                                         ||      		// RITM0083639
        dnsDomainIs(host, "k8s.gcr.io")                                     ||          	// RITM0083639
        dnsDomainIs(host, "registry.k8s.io")                                ||              // RITM0083639
        dnsDomainIs(host, "ghcr.io")                                        ||       		// RITM0083639
        dnsDomainIs(host, "docker.io")                                      ||            	// RITM0083639
        dnsDomainIs(host, "id.pagar.me") 				                    ||	            // RITM0089872
        dnsDomainIs(host, "my.salesforce.com") 			                    ||		        // RITM0090718
        dnsDomainIs(host, "login.salesforce.com") 		                    ||			    // RITM0090719
        dnsDomainIs(host, "boutique-dev-rebuild.hublot.com")                ||              // CHG0061104
        dnsDomainIs(host, "boutique-preprod-rebuild.hublot.com")            ||              // CHG0061104
        dnsDomainIs(host, "boutique-qa-rebuild.hublot.com")                 ||              // CHG0061104
        dnsDomainIs(host, "boutique.hublot.com")                            ||              // CHG0061104
        dnsDomainIs(host, "account-newhublot.hublot.com")                   ||              // CHG0061104
        dnsDomainIs(host, "account-preprod.hublot.com")                     ||              // CHG0061104
        dnsDomainIs(host, "account-qa.hublot.com")                          ||              // CHG0061104
        dnsDomainIs(host, "account.hublot.com")                             ||              // CHG0061104
        dnsDomainIs(host, "api-ecrm-preprod.hublot.com")                    ||              // CHG0061104
        dnsDomainIs(host, "api-nprod.hublot.com")                           ||              // CHG0061104
        dnsDomainIs(host, "api.hublot.com")                                 ||              // CHG0061104
        dnsDomainIs(host, "www.hublot.com")                                 ||              // CHG0061104
        dnsDomainIs(host, "wwwdrupal-preprod.hublot.com")                   ||              // CHG0061104
        dnsDomainIs(host, "saeuwhublotecomdevassets.blob.core.windows.net") ||              // CHG0061104
        dnsDomainIs(host, "saeuwhublotecompprassets.blob.core.windows.net") ||              // CHG0061104
        dnsDomainIs(host, "saeuwhublotecomprdassets.blob.core.windows.net") ||              // CHG0061104
        dnsDomainIs(host, "heritage.kenzo.com")                             ||              // RITM0091281
        dnsDomainIs(host, "berluti.com")                                    ||              // RITM0092316
        dnsDomainIs(host, "ca-lightrag-dev.orangeisland-6ab73a4a.westus3.azurecontainerapps.io")    ||                        // RITM0092446
        dnsDomainIs(host, "sephora.zanthusonline.com.br")                   ||              // RITM0092826
        dnsDomainIs(host, "sephorahml.zanthusonline.com.br")                ||              // RITM0093478
        dnsDomainIs(host, "sephorahml2.zanthusonline.com.br")               ||              // RITM0093478
        dnsDomainIs(host, "sephorahml3.zanthusonline.com.br")                               // RITM0093478
		)
		)
	return proxy_pzen;
	/* END Redirection to PZEN subcloud */
	

	/* Redirection to EMEA PZEN */
	if 	(
		(InternalNetwork == "TRUE")
		&&
		(
		dnsDomainIs(host, ".successfactors.com") || 										// RITM0013922
		dnsDomainIs(host, ".successfactors.eu") || 											// RITM0013922
		dnsDomainIs(host, "ville-bruyereslechatel.fr") || 									// RITM0022024
		isInNet(host, "91.194.100.237", "255.255.255.255") || 								// RITM0026337
		isInNet(host, "91.194.100.238", "255.255.255.255") || 								// RITM0026337
		isInNet(host, "91.194.100.239", "255.255.255.255") || 								// RITM0026337
		isInNet(host, "91.194.100.240", "255.255.255.255") || 								// RITM0026337
		isInNet(host, "91.194.100.241", "255.255.255.255") || 								// RITM0026337
		isInNet(host, "91.194.100.242", "255.255.255.255") || 								// RITM0026337
		shExpMatch(host, "217.169.48.114") || 												// RITM0013214 - Gwenael PIERSON
		dnsDomainIs(host, "www.ablon-sur-seine.fr") || 										// INC0026475
		dnsDomainIs(host, "www.asean-tmview.org") ||                    					// RITM0028891
		dnsDomainIs(host, "api.meraki.com") ||                    	        				// RITM0037850
		dnsDomainIs(host, "api.meraki.cn") ||                    	        				// RITM0037850
		dnsDomainIs(host, "prd-eorder-vip.eastasia.cloudapp.azure.com") ||					// CDC - Morgen Souissi
		dnsDomainIs(host, "uat-eorder-vip.eastasia.cloudapp.azure.com") ||  				// CDC - Morgen Souissi
		dnsDomainIs(host, "azflvaeuwwwwprd01cr.azurecr.io")	||								// RITM0028379 FLV Azure
		dnsDomainIs(host, "azflvaeuwwwwnonprd01cr.azurecr.io") ||							// RITM0028379 FLV Azure
		dnsDomainIs(host, "benefitce.com") ||                           					// RITM0028635	
		dnsDomainIs(host, "www.bretigny91.fr") || 											// INC0026475
		dnsDomainIs(host, "eapm.capgemini.com") ||											// Rerouting Capgemini to PZEN for MH
		dnsDomainIs(host, "90373904-test-retail-ondemand.cegid.cloud") || 					// Cegid Hublot
		shExpMatch(host, "preprod-ecom.chaumet.com")	|| 									// RITM0031104
        shExpMatch(host, "preprod-tma.chaumet.com")	|| 										// RITM0031104
		shExpMatch(host, "pr3pr0d-m4g3cyl.chaumet.com")	|| 									// RITM0031104
        shExpMatch(host, "www.chaumet.com")	|| 												// RITM0031104
		shExpMatch(host, "communications.christiandior.com") || 							// CDC - demande Morgen Souissi
		dnsDomainIs(host, "routematrix-bo.christiandior.com")	||							// CDC - Morgen Souissi
		dnsDomainIs(host, "lvmh.creditvoyager.com") || 										// RITM0026740 - Givenchy/Kenzo
		shExpMatch(host, "ps.dior.com") ||													// CDC - demande Morgen Souissi
		shExpMatch(host, "wps.dukhanbank.com") ||											// RITM0033902
		dnsDomainIs(host, "admin-expert.eilep.com") || 										// INC0027347
		dnsDomainIs(host, "elnet.fr") || 													// INC0027347
		dnsDomainIs(host, "lebonmarche.epresspack.us") ||									// RITM0032481
		dnsDomainIs(host, "lebonmarche.epresspack.me")||									// RITM0032481
		dnsDomainIs(host, ".etocrm.fr")	||													// RITM0032820 - CDC - IP Whitelisting
		shExpMatch(host, "asp.expedito.fr") ||												// CDC - demande Morgen Souissi - Solution etiquettage Blois
		shExpMatch(host, "rds.expedito.fr") ||												// CDC - demande Morgen Souissi - Solution etiquettage Blois
		dnsDomainIs(host, "hosting.fluidbook.com") || 										// RITM0029550_20210107_RAD
		shExpMatch(host, "admin-prd-az-www.fondationlouisvuitton.fr") ||					// RITM0028333 Fondation LV Vente privée
		shExpMatch(host, "admin-nonprd-az-www.fondationlouisvuitton.fr") ||					// RITM0028333 Fondation LV Vente privée
		shExpMatch(host, "admin-nonprdstg-az-www.fondationlouisvuitton.fr")	||				// RITM0028333 Fondation LV Vente privée
		shExpMatch(host, "admin-nonprdgrowth-az-www.fondationlouisvuitton.fr")	||			// RITM0036435
        shExpMatch(host, "admin-nonprdcare-az-www.fondationlouisvuitton.fr") ||				// RITM0036436
		shExpMatch(host, "admin-nonprd-az-app.fondationlouisvuitton.fr") ||					// RITM0028496 Fondation LV Vente privée
		shExpMatch(host, "admin-prd-az-app.fondationlouisvuitton.fr")	||					// RITM0028496 Fondation LV Vente privée	
		dnsDomainIs(host, "admin.galeriedior.com") ||                           			// RITM0034869
		dnsDomainIs(host, "securega.gestion-des-acces.fr") || 								// INC0027347
		dnsDomainIs(host, "fsrar.gov.ru") || 												// RITM0034707 - MHIS
		shExpMatch(host, "hello-click.com") || 												// RITM0034395
		shExpMatch(host, "chdiordev1aric.planning-analytics.ibmcloud.com") || 				// CDC - demande Morgen Souissi
		shExpMatch(host, "chdiorprod1ric.planning-analytics.ibmcloud.com") ||				// CDC - demande Morgen Souissi
		dnsDomainIs(host, "gitlab-lin5.lvmh.lbn.fr") ||										// RITM0026572
		dnsDomainIs(host, "kenora.moethennessy.com") ||                         			// INC0041429
		shExpMatch(host, "christiandiorprod.legisway.com")	||								// CDC - demande Morgen Souissi
		shExpMatch(host, "christiandiortest.legisway.com")	||								// CDC - demande Morgen Souissi											
		//dnsDomainIs(host, "qualiving.lvmh.com") || 											// RITM0029699_20210122_RAD
		dnsDomainIs(host, "dior-pcis-s.neolane.net") ||										// RITM0029272 SDU
		dnsDomainIs(host, "nxaas.neoxam.com") || 											// RITM0024507 - LVMH Holding
		dnsDomainIs(host, "ppr-gateway-crm-bluelink.odigo.cloud") || 						// CDC - Morgen Souissi
		dnsDomainIs(host, "dior.odigo.cx") ||												// CDC - Morgen Souissi	
		dnsDomainIs(host, "www.pressreader.com") || 										// RITM0030074_20210303_RAD																								
		dnsDomainIs(host, "lesechos-ws.prolexis.com") || 									// RITM0033891
		shExpMatch(host, "www.radioclassique.fr") ||                            			// INC0035138
		dnsDomainIs(host, "lesechos.clients.sdv.fr") ||										// RITM0034809
		dnsDomainIs(host, "24sevres.my.salesforce.com") || 									// RITM0026968
		dnsDomainIs(host, "24sevres--full.my.salesforce.com") ||  							// RITM0026968
		shExpMatch(host, "help.sofinord.com") || 											// RITM0034395
		dnsDomainIs(host, "istory.sofinord.com") || 										// INC0025763
		shExpMatch(host, "azflvaeuwmsiteprd01sa.blob.core.windows.net")	||					// RITM0028368 FLV Azure 
		shExpMatch(host, "azflvaeuwwwwprd01sa.blob.core.windows.net")	||					// RITM0028368 FLV Azure 
		shExpMatch(host, "azflvaeuwwwwprd01sa-secondary.blob.core.windows.net")	||			// RITM0028368 FLV Azure 
		shExpMatch(host, "azflvaeuwwwwnonprd01sa.blob.core.windows.net") ||					// RITM0028368 FLV Azure 
		shExpMatch(host, "azflvaeuwwwwnonprd02sa.blob.core.windows.net") ||					// RITM0028368 FLV Azure
		dnsDomainIs(host, "magic.x27crm.com") ||											// RITM0029272 SDU
		dnsDomainIs(host, "dior.zportal.it") 	||											// CDC - Morgen Souissi	
		dnsDomainIs(host, "sftp2.prowebce.net") ||                              			// RITM0036957
		dnsDomainIs(host, "thalie-sante.uegar.com") ||										// RITM0037204
		dnsDomainIs(host, ".lesjourneesparticulieres.com") ||								// RITM0037728
		shExpMatch(host, "espaceclient.sepalia.fr") ||		                    			// RITM0048577
		dnsDomainIs(host, "sloanreview.mit.edu") ||											// RITM0035382
	    dnsDomainIs(host, "webedito.service.dev.gcp.eilep.io")    ||                        // RITM0051490
        dnsDomainIs(host, "webedito.service.ppd.gcp.eilep.io")    ||                        // RITM0051490
        dnsDomainIs(host, "etl.service.dev.gcp.eilep.io")    ||                             // RITM0051490
        dnsDomainIs(host, "etl.service.ppd.gcp.eilep.io")   ||                             	// RITM0051490
		dnsDomainIs(host, "test-feed.boursier.com") ||                          // RITM0054879
        shExpMatch(host, "lvmhappening.com")  ||                                // RITM0055811
        dnsDomainIs(host, "tagpp-externalapi-was.aitcentral.com")  ||           // RITM0056314
        dnsDomainIs(host, "consulat.gouv.fr") ||                                // RITM0056016
        dnsDomainIs(host, "monespaceprive.msa.fr")  ||                          // RITM0056187
        dnsDomainIs(host, "resultats-elections.interieur.gouv.fr")  ||          // RITM0056933
        dnsDomainIs(host, "results-elections.secvoting.com")   ||               // RITM0057140
        dnsDomainIs(host, "dsb-rimowa.allshare-scenario.fr")   ||               // RITM0057509
        dnsDomainIs(host, ".service.dev.gcp.eilep.io")   ||                     // RITM0058901
        dnsDomainIs(host, ".service.ppd.gcp.eilep.io")   ||                     // RITM0058901
        dnsDomainIs(host, ".sitefactory.service.dev.gcp.eilep.io")   ||         // RITM0058901
        dnsDomainIs(host, ".sitefactory.service.ppd.gcp.eilep.io")   ||           // RITM0058901
        dnsDomainIs(host, ".kenzo-vpc-net-tools-test.de-c1.cloudhub.io") ||      // RITM0059521
        dnsDomainIs(host, "riskmanagement.my.salesforce-sites.com")  ||         // RITM0061030
        dnsDomainIs(host, "bo-stage.lesechos.fr")   ||    		                // RITM0062674
        dnsDomainIs(host, "cms.medusa.sfr.net")     ||		                    // RITM0062873
		shExpMatch(url, "gitlab.com/les-echos/*")   ||                          // RITM0076165
        dnsDomainIs(host, "sdv.groupelesechos.fr")  ||   		                // RITM0064574
        dnsDomainIs(host, "paris-paradis.leparisien.fr")  ||     		        // RITM0064669
        dnsDomainIs(host, "sep5-prod-a5b4adf5.cloud.maxxing.com") ||            // RITM0065268
        dnsDomainIs(host, "myteamsrh-009.cegedim-srh.net")   ||                 // RITM0065860
        dnsDomainIs(host, "lbm1-dev-a5137dff.cloud.maxxing.com")   ||           // RITM0066837
        dnsDomainIs(host, "kuflduktui-public.bastionhost.aliyuncs.com")   ||      // RITM0067266
        dnsDomainIs(host, ".medicitv.fr")   ||                                    // RITM0068469
        dnsDomainIs(host, "api-preprod.axiocap.com")   ||                         // RITM0068588
        dnsDomainIs(host, "api.axiocap.com")    ||                                // RITM0068589
        dnsDomainIs(host, "partners.oneaccess.lvmh.com")     ||                   // RITM0068626
        dnsDomainIs(host, "tc-tsv2.belmond.com")        ||                        // RITM0073055
        dnsDomainIs(host, "voyager.eurostar.com")       ||                        // RITM0073079
        dnsDomainIs(host, "aks-weu-trust-sandbox-qgoqwb8a.hcp.westeurope.azmk8s.io")    ||                          // RITM0073192
        dnsDomainIs(host, "dns-aks-container-trust-hosting-weu-sandbox-0ntryphu.hcp.westeurope.azmk8s.io") 	||		// RITM0074136
        dnsDomainIs(host, "ech.oversoc.com")          ||                        // RITM0074244
        dnsDomainIs(host, "front.chatbot-dev.lesechosleparisien.fr")         ||                                     // RITM0075690
        dnsDomainIs(host, "ia-api.livemixr.com") ||                       // RITM0075746
        dnsDomainIs(host, "menu-strapi-dev.livemixr.com") ||              // RITM0075746
        dnsDomainIs(host, "menu-strapi-demo.livemixr.com") ||             // RITM0075746
        dnsDomainIs(host, "lp-menu-demo.livemixr.com") ||                 // RITM0075746
        dnsDomainIs(host, "lp-menu-dev.livemixr.com") ||                  // RITM0075746
        dnsDomainIs(host, "lp-menu-production.livemixr.com") ||           // RITM0075746
        dnsDomainIs(host, "lp-jobber.livemixr.com") ||                    // RITM0075746
        dnsDomainIs(host, "lab-dev.livemixr.com") ||                      // RITM0075746
        dnsDomainIs(host, "lab-sandbox.livemixr.com") ||                  // RITM0075746
        dnsDomainIs(host, "dlp-jobber.livemixr.com")  ||                  // RITM0075746
        dnsDomainIs(host, "portail.cartes-bancaires.com")    ||           // RITM0076199
        dnsDomainIs(host, "pageturner.medici.tv")     ||                  // RITM0076505,RITM0083907
        dnsDomainIs(host, "legacy.prod.medicitv.fr")    ||                // RITM0076506
        dnsDomainIs(host, "vizoncb.cartes-bancaires.com")     ||          // RITM0076952
        dnsDomainIs(host, "securepay.belmond.com")            ||         // RITM0077430
        shExpMatch(host, "89.105.65.162")                     ||         // RITM0077767
        dnsDomainIs(host, "kibana.mgmt.prd.gcp.eilep.io")       ||       // RITM0078042
        dnsDomainIs(host, "grafana.mgmt.prd.gcp.eilep.io")      ||       // RITM0078046
        dnsDomainIs(host, "kibana.mgmt.ppd.gcp.eilep.io")       ||       // RITM0078047
        dnsDomainIs(host, "grafana.mgmt.ppd.gcp.eilep.io")      ||       // RITM0078048
        dnsDomainIs(host, "www.annonces-legales.fr")            ||       // RITM0078170
        dnsDomainIs(host, "opinionway.ai")                      ||       // RITM0078230
        dnsDomainIs(host, "www-ui.belmond.com")                 ||       // RITM0078330
        dnsDomainIs(host, "admin.profile.staging.parismatch.com") ||     // RITM0079128
        dnsDomainIs(host, "admin.profile.parismatch.com")       ||       // RITM0079128
        dnsDomainIs(host, "echos-portailsol-web.sdv.fr")        ||       // RITM0079878
        dnsDomainIs(host, "echos-solutions-web.sdv.fr")         ||      // RITM0079879
        dnsDomainIs(host, "testbelmond.teracenter.it")          ||      // RITM0080397
        dnsDomainIs(host, "krug-suivi-citernes.technord.com")   ||      // RITM0080417
        dnsDomainIs(host, "experience.adobe.com")               ||        // RITM0080765
        dnsDomainIs(host, "eu.business-api.amazon.com")         ||        // RITM0081067
        dnsDomainIs(host, "printix.net")      		            ||         // RITM0081068
        dnsDomainIs(host, "www-preview.belmond.com")            ||         // RITM0082405
        dnsDomainIs(host, "jirah.olisnet.com")                  ||           // RITM0082671
        dnsDomainIs(host, "amazon.it")                          ||             // RITM0082982
        dnsDomainIs(host, "agent-test.lesechosleparisienservices.fr") ||				// RITM0083829
        dnsDomainIs(host, "agent-preprod.lesechosleparisienservices.fr") ||				// RITM0083829
        dnsDomainIs(host, "lep.expert-infos.com") 						||				// RITM0083830
        dnsDomainIs(host, "agent-test.lesechosleparisienservices.fr") ||				// RITM0083829
        dnsDomainIs(host, "agent-preprod.lesechosleparisienservices.fr") ||				// RITM0083829
        dnsDomainIs(host, "lep.expert-infos.com") 						 ||				// RITM0083830
        dnsDomainIs(host, "abonnes.efl.fr")                       ||         // RITM0083918
        dnsDomainIs(host, "revuefiduciaire.grouperf.com")         ||         // RITM0083918
        dnsDomainIs(host, "securega.gestion-des-acces.fr")        ||         // RITM0083918
        dnsDomainIs(host, "www.gestiondefortune.com")             ||         // RITM0083918
        dnsDomainIs(host, "www.agefi.fr")                         ||         // RITM0083918
        dnsDomainIs(host, "www.staging.parismatch.com")           ||         // RITM0085090
        dnsDomainIs(host, "titan.belmond.com")                    ||       // RITM0085090
        dnsDomainIs(host, "cloud-h360.vivetic.com")               ||          // RITM0086376
        dnsDomainIs(host, "dwalp.org")                            ||          // RITM0087445
        dnsDomainIs(host, "livemixr.com")                         ||          // RITM0087446
        dnsDomainIs(host, "bcext.nobilis-group.net")              ||            // RITM0088131
        dnsDomainIs(host, ".pub.groupelesechos.fr")               ||            // RITM0090685
        dnsDomainIs(host, ".pub.lesechosleparisien.fr")           ||            // RITM0090685
        dnsDomainIs(host, "ext.groupelesechos.fr")               ||            // RITM0091453
        dnsDomainIs(host, "ext.lesechosleparisien.fr")           ||            // RITM0091453
        dnsDomainIs(host, "ext.lesechos.fr")                     ||            // RITM0091453
        dnsDomainIs(host, "ext.lesechosleparisienservices.fr")   ||            // RITM0091453
        dnsDomainIs(host, "ext.leparisien.fr")                   ||            // RITM0091453
        dnsDomainIs(host, "ext.parismatch.fr")                   ||            // RITM0091453
        dnsDomainIs(host, "ext.agence-nsw.fr")                   ||            // RITM0091453
        dnsDomainIs(host, "ext.lesechos-publishing.fr")          ||            // RITM0091453
        dnsDomainIs(host, "ext.annonces-legales.fr")             ||           // RITM0091854
        dnsDomainIs(host, "ext.odella.fr")                       ||             // RITM0091854
        dnsDomainIs(host, "*.staging-services.lesechos.fr")                // RITM0093055
        )
		)
	return "PROXY emea-private-zscaler.proxy.lvmh:443; DIRECT";
	/* END Redirection to EMEA PZEN */
	
	/* Redirection to EMEA PZEN - No DIRECT */	
	if (
		dnsDomainIs(host, "chaumet.legisway.com") ||										// RITM0027288 - Chaumet
		dnsDomainIs(host, "fendi.legisway.com") || 					    					// RITM0028145
		shExpMatch(url, "http://pressroom-lesechos-leparisien.com/wp-login.php") 			// RITM0027609
		)
	return "PROXY emea-private-zscaler.proxy.lvmh:443";	
	/* END Redirection to EMEA PZEN - No DIRECT */	
	
		/* Redirection to Singapore PZEN INC0047570 */		
	if (

		dnsDomainIs(host, "admin-th.luxola.com")  ||	                        			// RITM0040243
		dnsDomainIs(host, "admin.luxola.com")	||	                            			// RITM0040243
		dnsDomainIs(host, "admin-hk.luxola.com") ||	                          		 		// RITM0040243
		dnsDomainIs(host, "admin-kr.luxola.com") ||	                           				// RITM0040243
		dnsDomainIs(host, "times-parking-monthly.com.my") ||	                			// INC0066537
		dnsDomainIs(host, "admin-id.luxola.com")	                        				// RITM0040243
		)
	return "PROXY singapore-private-zscaler.proxy.lvmh:443; DIRECT";	
	/* END Redirection to Singapore PZEN INC0047570 */	
	
	/* Redirection to New York PZEN */
	if (
		dnsDomainIs(host, "www.izipay.pe")  ||                                                  //RITM0082614
		dnsDomainIs(host, "casilla.mtc.gob.pe")    ||                                           //RITM0083183
		dnsDomainIs(host, "sat.gob.mx")                                                         //RITM0088632
		)
	return "PROXY secaucus-private-zscaler.proxy.lvmh:443; DIRECT";
	/* Redirection to New York PZEN */


	/* Redirection to direct for MHIS -  site n2.meraki.cn  we-legal.mhd.com.cn - INC0092223  */																						
	if 
      (
         (shExpMatch(country,"Singapore"))
      &&
         (dnsDomainIs(host,"n2.meraki.cn")) || 
      	 (dnsDomainIs(host,"mhd.peoplus.cn")) ||
	     (dnsDomainIs(host,"we-legal.mhd.com.cn"))
		)
       return "DIRECT";
       /* END Redirection to direct for MHIS -  site n2.meraki.cn  we-legal.mhd.com.cn - INC0092223  */	
       
 
		/* To redirect MH users from Singapore to China PZEN for few China URLs INC0066145 */
    if (
         (isInNet(User_Lan_IP, "10.62.152.0" , "255.255.252.0"))
      &&
         (dnsDomainIs(host,"mhd.peoplus.cn")) ||
        // (dnsDomainIs(host,"aliyun.com"))   ||                                // INC0073429
          (dnsDomainIs(host,"we-legal.mhd.com.cn"))                            // RITM0057530
       )
       return "PROXY auth-china-private-zscaler.proxy.lvmh:443; DIRECT";
       /* to redirect MH users from Singapore to China PZEN for few China URLs INC0066145 */
       


       /* Redirection of flexerpcloud.flexsystem.cn to SH3 PZEN due to slowness in accessing from Hongkong -  INC0249369-RITM0087488*/																						
	if 
      (
         (shExpMatch(country,"Hongkong"))
          &&
	  (dnsDomainIs(host,"flexerpcloud.flexsystem.cn"))
	)
       return "PROXY auth-china-private-zscaler.proxy.lvmh:443; DIRECT";
      /* END Redirection of flexerpcloud.flexsystem.cn to SH3 PZEN due to slowness in accessing from Hongkong -  INC0249369-RITM0087488*/
    
      
		/* Redirect Fashion HK site users to China PZEN due to slowness in accessing Aliyun- INC0144393 -RITM0075864 -INC0190432 */
        if (
        (isInNet(User_Lan_IP, "10.90.232.0", "255.255.252.0"))
		&&
        ((dnsDomainIs(host,"aliyun.com")) ||
        (dnsDomainIs(host,"aliyuncs.com")) ||
        (dnsDomainIs(host,"alicdn.com")) ||
        (dnsDomainIs(host,"mmstat.com")))
        )
        return "PROXY auth-china-private-zscaler.proxy.lvmh:443; DIRECT";
        /* END Redirect Fashion HK site users to China PZEN due to slowness in accessing Aliyun- INC0144393 -RITM0075864 -INC0190432 */
        

		/* Redirection to China PZEN  for Sephora users from SEA for a China URL */
   if (
       (
                 (isInNet(User_Lan_IP, "10.158.229.0" , "255.255.255.0"))      ||
		 (isInNet(User_Lan_IP, "10.158.216.128" , "255.255.255.192"))  ||
		 (isInNet(User_Lan_IP, "10.158.206.0" , "255.255.255.128"))    ||
		 (isInNet(User_Lan_IP, "10.158.208.128" , "255.255.255.192"))  ||
		 (isInNet(User_Lan_IP, "10.158.210.128" , "255.255.255.192"))  ||
		 (isInNet(User_Lan_IP, "10.158.222.0" , "255.255.254.0"))      ||
		 (isInNet(User_Lan_IP, "10.158.232.0" , "255.255.255.0"))      ||
		 (isInNet(User_Lan_IP, "10.158.214.128" , "255.255.255.192"))  ||
		 (isInNet(User_Lan_IP, "10.158.207.128" , "255.255.255.128"))  ||
		 (isInNet(User_Lan_IP, "10.157.165.90" , "255.255.255.254"))  || // INC0179800
         (isInNet(User_Lan_IP, "10.157.110.212" , "255.255.255.252"))  || // INC0179800
         (isInNet(User_Lan_IP, "10.157.75.154" , "255.255.255.254"))  || // INC0179800
         (isInNet(User_Lan_IP, "10.157.116.84" , "255.255.255.252"))  || // INC0179800
         (isInNet(User_Lan_IP, "10.157.65.148" , "255.255.255.252"))  || // INC0179800
         (isInNet(User_Lan_IP, "10.157.94.90" , "255.255.255.254"))  || // INC0179800
         (isInNet(User_Lan_IP, "10.157.175.218" , "255.255.255.254"))  || // INC0179800
         (isInNet(User_Lan_IP, "10.157.117.90" , "255.255.255.254"))  || // INC0179800
         (isInNet(User_Lan_IP, "10.157.171.90" , "255.255.255.254"))  || // INC0179800
         (isInNet(User_Lan_IP, "10.157.126.174" , "255.255.255.254"))  || // INC0179800
         (isInNet(User_Lan_IP, "10.157.65.150" , "255.255.255.255"))   || 
		 (isInNet(User_Lan_IP, "10.157.115.85" , "255.255.255.255"))	||	// RITM0076694
        (isInNet(User_Lan_IP, "10.157.115.86" , "255.255.255.255"))	||	// RITM0076694
        (isInNet(User_Lan_IP, "10.157.88.21" , "255.255.255.255"))	||	// RITM0076694
        (isInNet(User_Lan_IP, "10.157.88.22" , "255.255.255.255"))	||	// RITM0076694
        (isInNet(User_Lan_IP, "10.157.118.154" , "255.255.255.255"))	||	// RITM0076694
        (isInNet(User_Lan_IP, "10.157.118.155" , "255.255.255.255"))	||	// RITM0076694
        (isInNet(User_Lan_IP, "10.157.165.90" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.165.91" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.110.213" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.110.214" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.75.154" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.75.155" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.116.85" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.116.86" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.65.149" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.65.150" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.94.90" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.94.91" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.175.218" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.175.219" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.117.90" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.117.91" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.171.90" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.171.91" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.126.174" , "255.255.255.255")) ||		// RITM0079193
		(isInNet(User_Lan_IP, "10.157.126.175" , "255.255.255.255")) 		// RITM0079193
		)
     &&
         (dnsDomainIs(host,".ecosaas.com"))    // RITM0059668
      )
   return "PROXY auth-china-private-zscaler.proxy.lvmh:443; DIRECT";
	   
	   	   /*  END Redirection to China PZEN  for Sephora users from SEA for a China URL */   
	   	   
	/* Specifique Hublot */ 
	if 	(
		(isInNet(User_Lan_IP, "10.88.140.0", "255.255.252.0")
		)
    &&
		(
		dnsDomainIs(host, "sophiemallebranche.com") 	// RITM0064063															  
		)
		)
	return "PROXY par2.sme.zscloud.net:443; PROXY par4.sme.zscloud.net:443; DIRECT";
		/* END Specifique Hublot */
			
	/************************************************/
	/*												*/
	/* 		Specific rerouting to public ZEN  		*/
	/*												*/
	/************************************************/
	
	
	
	
	
	
	
	
	    /* Redirection to SinV  due to performance issue for MH INC0192994 */
	// if (
	// isInNet(public_ip, "180.232.122.66", "255.255.255.255" ) 				
	//   )                                   
	// return "PROXY sin5.sme.zscloud.net:443; DIRECT";
	/* end Redirection to SinV  due to performance issue for MH INC0192994*/
	
	
	
//	if 
//      (
//         (shExpMatch(country,"China"))
//      &&
//         (dnsDomainIs(host,"wxapp.tc.qq.com"))  ||    
//         (shExpMatch(host, "wxapp.tc.qq.com"))  ||
//		 (dnsDomainIs(host,".qq.com"))	        ||    
//         (shExpMatch(host, ".qq.com"))  ||
//		 (dnsDomainIs(host,".qq.com.cn"))  ||    
//         (shExpMatch(host, ".qq.com.cn"))   
//
//		)
//
//	{
//	return "PROXY bjs3.sme.zscloud.net:443; DIRECT";
//	}

	if (
		dnsDomainIs(host, "tiffanyandco.app.box.com")  ||
		dnsDomainIs(host, "tiffanyandco.app.box.com") 
		)
		
return "PROXY auth-china-private-zscaler.proxy.lvmh:443; DIRECT";

	
/* Redirection of eportal.incometax.gov.in to SH3 PZEN due to inaccessible from SH3 Public node Hongkong -  INC0278216*/
    if 	(
         shExpMatch(country,"Hong Kong") 
         && 
        dnsDomainIs(host, "eportal.incometax.gov.in")||
        shExpMatch(host, "eportal.incometax.gov.in")
	)  
    return "PROXY bjs3.sme.zscloud.net:443; DIRECT";
/* END Redirection of eportal.incometax.gov.in to SH3 PZEN due to inaccessible from SH3 Public node Hongkong -  INC0278216*/
	
/* Redirection to Milan DCINC0233724*/
    if (                              
    (shExpMatch(country,"United Arab Emirates")||shExpMatch(country,"Saudi Arabia"))
    &&
    dnsDomainIs(host, "corefa-buyer.sephora.fr")
    )
    return "PROXY mil3.sme.zscloud.net:443; DIRECT";

/* END Redirection of specific  INC0233724 */
	
/* INC0146623-INC0205432 - Redirecting Taxbill website to specific Zscaler DC in Seoul */
    if 	(
         shExpMatch(country,"South Korea") 
         && 
        dnsDomainIs(host, "home.taxbill365.com") ||
        shExpMatch(host, "home.taxbill365.com")
	)  
    return "PROXY 165.225.228.47:443; PROXY tyo4.sme.zscloud.net:443; DIRECT";
/* Redirection of URL store.shopping.yahoo.co.jp to Japan for France MH users */
    if (
        shExpMatch(country,"France")
        &&
        dnsDomainIs(host, "store.shopping.yahoo.co.jp") ||
        dnsDomainIs(host, ".yimg.jp")                         //RITM0089822
    )
    return "PROXY tyo4.sme.zscloud.net:443; DIRECT";
/* END Redirection */

/* Redirection of chanel.com via Zscaler US public DC for Argentina users -  INC0298039*/
    if 	(
         shExpMatch(country,"Argentina") 
         && 
        dnsDomainIs(host, "chanel.com")||
        shExpMatch(host, "chanel.com")
	)  
    return "PROXY nyc4.sme.zscloud.net:443; DIRECT";
/* END of edirection of chanel.com via Zscaler public DC in US for Argentina users -  INC0298039*/

/* Redirection of URL concursolutions.com &  yamaya.jp to Japan service edge for Japan MH users */	
if 
      (
         (shExpMatch(country,"Japan"))
      &&
         (dnsDomainIs(host,"concursolutions.com")) ||	//RITM0092219
         (dnsDomainIs(host,"yamaya.jp")) ||	            //RITM0092219
         (shExpMatch(host, "concursolutions.com"))  	//RITM0092219
		)

	{
	return "PROXY tyo4.sme.zscloud.net:443; DIRECT";
	}
/* END of Redirection */

/* INC0146623-INC0205432 - Redirecting Taxbill website to specific Zscaler DC in Seoul */


	
	/* Redirection to Milan as connection from Zscaler node towards EDF block INC0153649 */
     if (
        (
        (isInNet(public_ip, "194.3.170.9", "255.255.255.255"))||
        (isInNet(public_ip, "104.245.119.114", "255.255.255.255"))
     
        )
        &&
        (
        dnsDomainIs(host, "sei-ael-guadeloupe.edf.com") // INC0037895
        )
        )
	return "PROXY mil3.sme.zscloud.net:80;DIRECT";	
	/* END Redirection to Milan as connection from Zscaler node towards EDF block INC0153649 */
	
	/* Redirection to PZEN  as connection are intermittemt from Public Zen  INC0185183 */
if 	(
			(InternalNetwork == "TRUE")
			&&
			(			         
			dnsDomainIs(host, "insight-cube.miaozhen.com") 	||                   
			shExpMatch(host, "insight-cube.miaozhen.com")    ||
			dnsDomainIs(host, "app.convertlab.com") 	||                   
		    shExpMatch(host, "app.convertlab.com")
					)
			)
		return "PROXY auth-china-private-zscaler.proxy.lvmh:443; PROXY 10.104.248.251:443; DIRECT";	
		
/* End of Redirection to PZEN  as connection are intermittemt from Public Zen  INC0185183 */

/* INC0154611 - Access of Rednote Social Listening Platform redirect to bjs1 and Bjs3 */
    if (
		dnsDomainIs(host, "idea.xiaohongshu.com")
	
		)
	return "PROXY bjs1.sme.zscloud.net:443; PROXY bjs3.sme.zscloud.net:443; DIRECT";	
/* INC0154611 - Access of Rednote Social Listening Platform redirect to bjs1 and Bjs3 */

/* INC0226388 Redirection-Los Angeles World Airports redirection to AMER DC   */

    if (
		dnsDomainIs(host, "lawa.diversitycompliance.com") 
		
		)
	return "PROXY dfw1-2.sme.zscloud.net:443; PROXY qla2.sme.zscloud.net:443; DIRECT";	

/* End of Redirection Los Angeles World Airports redirection to AMER DC -INC0226388  */	
	
	/* Redirect users to Saitel - INC0139552 */
//	if (
//	    isInNet(public_ip, "172.85.176.130", "255.255.255.255" )
//	    )                                   
//	return "PROXY sea1.sme.zscloud.net:443; DIRECT";
	
/* end Redirect users to Saitel - INC0139552 */
	
	/* RITM0060492 - Due to issues with Hong Kong DC with this website is now sent to Sha2 and Bjs3 */
    if (
		dnsDomainIs(host, "xh.newrank.cn")  ||
		dnsDomainIs(host, "chs.newrank.cn") ||
		dnsDomainIs(host, "n1.newrank.cn")  ||
		dnsDomainIs(host, "gw.newrank.cn")
		)
	return "PROXY sha2.sme.zscloud.net:443; PROXY bjs3.sme.zscloud.net:443; DIRECT";	
	/* RITM0060492 - Due to issues with Hong Kong DC with this website is now sent to Sha2 and Bjs3 */
	
	

	/* Redirection to Milan as connection from Zscaler node of Tel-Aviv are blacklisted */
	if (
		dnsDomainIs(host, "efatura.snitechnology.net")  ||
		dnsDomainIs(host, "webapp.buis.com.tr")                         // RITM0065182
		)
	return "PROXY mil3.sme.zscloud.net:80; PROXY 221.122.91.36:80; DIRECT";	
	/* END Redirection to Milan as connection from Zscaler node of Tel-Aviv are blacklisted */

    /* RITM0040782 - Smartmessage is only available in Korea */
	if (
		dnsDomainIs(host, "smartmessage.plus.kt.com")
		)
	return "PROXY sel1.sme.zscloud.net:80; PROXY 221.122.91.36:80; DIRECT";	
	/* END RITM0040782 - Smartmessage is only available in Korea */
	
	/* INC0063553 - Latency to application hosted in Frankfurt */
	if (
		dnsDomainIs(host, "mtce2.oracleindustry.com") ||
		dnsDomainIs(host, "he13-ssd-ohs.oracleindustry.com")
		)
	return "PROXY fra4-2.sme.zscloud.net:443; PROXY 58.220.95.15:443; DIRECT";	
	/* END INC0063553  - Latency to application hosted in Frankfurt */
	
	/* Redirect traffic from Kazakhstan to Frankfurt instead of India RITM0071775 */
      if (
          shExpMatch(country,"Kazakhstan")
          )
		return "PROXY fra6.sme.zscloud.net:80; PROXY cph2.sme.zscloud.net:80; DIRECT";
    /* END Redirect traffic from Kazakhstan to Frankfurt instead of India  RITM0071775 */
	
	/* Redirection to Hong Kong because of performance issues on Taipei node */
	if (
		(isInNet(myIpAddress(), "10.247.5.0", "255.255.255.0"))    							// INC0035254 IP range for TW Office's Ips     	
		)
	 return "PROXY hkg3.sme.zscloud.net:80; DIRECT";
	/* END Redirection to Hong Kong because of performance issues on Taipei node */
	
	/* Redirection to Zurich for users in Italy  because of performance issues on path to Milan - INC0051144 */
	
	/* INC0053303 Redirect MH MX to Nuevo Laredo DC instead of Mexico I */
	if (
	isInNet(public_ip, "189.206.145.141", "255.255.255.255" ) 								// MH MX location
	   )                                   
	return "PROXY nld1.sme.zscloud.net:443; PROXY mex1.sme.zscloud.net:443; DIRECT";
	/* END INC0053303 Redirect MH MX to Nuevo Laredo DC instead of Mexico I */
	
	
	/* Redirection to Vienna for users in Turkey because of performance issues on path to Tel-Aviv - INC0035755 */
	if (
		shExpMatch(country,"Turkey")
		)
	return "PROXY vie1.sme.zscloud.net:443; DIRECT";
	/* END Redirection to Vienna for users in Turkey because of performance issues on path to Tel-Aviv - INC0035755 */
	
	/* Redirection to Johannesburg for users in South Africa because of high usage on Cape Town DC */
	if (
		shExpMatch(country,"South Africa")
		)
	return "PROXY jnb3.sme.zscloud.net:443; PROXY jnb2.sme.zscloud.net:443; DIRECT";
	/* END Redirection to Johannesburg for users in South Africa because of high usage on Cape Town DC */
	
	/* INC0041929 Redirect Czech user from Vienna to Munich due to performance issues */
	if (
	isInNet(public_ip, "176.97.14.146", "255.255.255.255" ) 								// Rimowa location in Czech Republic
	   )                                   
	return "PROXY muc1.sme.zscloud.net:443; PROXY 147.161.192.47:80; DIRECT";
	/* END INC0041929 Redirect Czech user from Vienna to Munich due to performance issues */
	
	/* Redirection to London instead of Manchester du to performance issue for Bulgari in Ireland */
	if (
		isInNet(public_ip, "89.100.176.234", "255.255.255.255")
		)
	return "PROXY lon3-2.sme.zscloud.net:443; PROXY 147.161.192.47:80; DIRECT";
	/* END Redirection to London instead of Manchester du to performance issue for Bulgari in Ireland */
	
																							
	if 
      (
         (shExpMatch(country,"Singapore"))
      &&
         (dnsDomainIs(host,"n5.meraki.cn")) || 
         (dnsDomainIs(host,"n2.meraki.cn"))
       )
       return "PROXY bjs3.sme.zscloud.net:443 ; PROXY sha2.sme.zscloud.net:443 ;  DIRECT";
       /* END Redirection to BJS3/SHA2 for singapore user - INC0051451 and INC0056656 */


	  /* Restricted to select San Francisco IV For Saipan and Guam users */
    if (
        isInNet(public_ip, "202.88.67.192", "255.255.255.248") ||                   		// INC0049703
        isInNet(public_ip, "202.128.25.144", "255.255.255.240") ||    
        isInNet(public_ip, "202.151.85.112", "255.255.255.248")                     		// INC0054059
        )
    return "PROXY sjc4-2.sme.zscloud.net:443;  PROXY 147.161.192.47:80; DIRECT" ;
    /* End Restricted to select US DC For Saipan users */
	
 
	/* Redirection to Singapore IV because of latency to Taipei DC --- INC0047182 */

    if (
        shExpMatch(country,"Philippines")
        )   

        return "PROXY sin4.sme.zscloud.net:443; PROXY 147.161.192.47:80; DIRECT";

    /* END Redirection to Singapore IV because of latency to Taipei DC*/
    
    
    /* Redirection to Munich  due to performance issue for Rimowa INC0051470 */
	if (
	isInNet(public_ip, "89.1.82.218", "255.255.255.255" ) 				
	   )                                   
	return "PROXY muc1.sme.zscloud.net:443; DIRECT";
	/* end Redirection to Munich  due to performance issue for Rimowa INC0051470 */
	
	/* Redirection to Sydney for Concursolutions website instead of Melbourne due to INC0047278 based on LAN subnet of DCA and CMV sites*/
	if (
	    (
		(isInNet(User_Lan_IP, "10.7.132.0", "255.255.255.0"))||
		(isInNet(User_Lan_IP, "10.7.128.0", "255.255.255.0"))||
		(isInNet(User_Lan_IP, "10.7.228.0", "255.255.255.0"))
		)
		)
	return "PROXY syd3.sme.zscloud.net:443; DIRECT";	
    /* END Redirection to Sydney for Concursolutions website instead of Melbourne due to INC0047278 based on LAN subnet of DCA and CMV sites */
    
    /* Redirection for users in Japan because of issues for tracking.launchmetrics.com  - INC0083627 */
	if (
		shExpMatch(country,"Japan") && dnsDomainIs(host, "tracking.launchmetrics.com")
		)
		{
	return "PROXY sel1.sme.zscloud.net:443; PROXY 147.161.192.47:80; DIRECT";
	}
	
	/* END Redirection for users in Japan because of issues for tracking.launchmetrics.com  - INC0083627 */

    /* Redirect CBI users in Saint Barth to Bogota due to latency on Miami - CHG0047015 */
	if (
	    isInNet(public_ip, "208.91.193.253", "255.255.255.255" ) ||							// Dauphin Telecom
	    isInNet(public_ip, "104.245.119.114", "255.255.255.255" ) 							// Digicel
	    )                                   
	return "PROXY bog1.sme.zscloud.net:443; PROXY 147.161.192.47:80; DIRECT";
    /* END Redirect CBI users in Saint Barth to Bogota due to latency on Miami  - CHG0047015 */
    
   /* INC0205097 Redirecting mhd website to Tokyo4 Proxy for which Zscaler IPs are whitelisted, Old entry edited */
	if (
		dnsDomainIs(host, "www.mhd-app.com") || 
			dnsDomainIs(host, "usui-dept.co.jp")    //INC0071131 and INC0071132
		)
	return "PROXY tyo4.sme.zscloud.net:80; PROXY 221.122.91.36:80; DIRECT";	
	/* END INC0205097 Redirecting mhd website to Tokyo4 Proxy for which Zscaler IPs are whitelisted, Old entry edited */	

/* To redirect Berluti INC0089925 */ 
   if (
       (
                 (isInNet(public_ip, "210.13.75.186", "255.255.255.248"))
		)
     &&
         (dnsDomainIs(host,"app.mural.co")) 
      )
  return "PROXY sin4.sme.zscloud.net:80; PROXY 147.161.192.47:80; DIRECT" ;
   
/*  END redirect Berluti INC0089925 */	

	/* Redirection of specific Gov website to Zurich and Munich for users in Italy because Website is rejecting the connection from some of the Milan ZS DC SMEs */
    if (                                // INC0145910
    shExpMatch(country,"Italy")
    &&
    dnsDomainIs(host, "www.co.lavoro.gov.it")
    )
    return "PROXY zrh1-2.sme.zscloud.net:443; PROXY muc1.sme.zscloud.net:443; DIRECT" ;

	/* END Redirection of specific Gov website to Zurich and Munich for users in Italy because Website is rejecting the connection from some of the Milan ZS DC SMEs */
	
  	/* RITM0073700 - Redirecting Huawei website to specific Zscaler DC */
    if 	(
         (
		  shExpMatch(country,"Singapore") ||
		  shExpMatch(country,"Malaysia")
		  )
         && 
         (dnsDomainIs(host, "huaweicloud.com"))
	    )  
    return "PROXY bjs3.sme.zscloud.net:443; PROXY sha2.sme.zscloud.net:443; DIRECT";
  /* RITM0073700 - Redirecting Huawei website to specific Zscaler DC */
    
    /* Redirect users SeyChells to JNB3 because of speed issue via ZIA- INC0159702/RITM0076223 */
	if (
	    isInNet(public_ip, "41.86.56.41", "255.255.255.255" )
	    )                                   
	return "PROXY jnb3.sme.zscloud.net:443; DIRECT";
    /* END redirect users SeyChells to JNB3 because of speed issue via ZIA- INC0159702/RITM0076223 */
    
    
/* Redirection to Amsterdam DC INC0233673*/
    if (                              
    shExpMatch(country,"The Netherlands")
    &&
    dnsDomainIs(host, "bijoumoderne.nl")
    )
    return "PROXY ams3.sme.zscloud.net:443; DIRECT";

/* END Redirection of specific  INC0233673 */
  


    /****************************************************************************/
	/*																			*/
	/* 	Temporary redirection for Tiffany due to Maxmind geolocation issue		*/
	/*																			*/
	/****************************************************************************/	
	
    /* Hong Kong */
	if (
		isInNet(public_ip, "62.221.158.56", "255.255.255.248" ) ||							// Tiffany Hong Kong - TST Office
		isInNet(public_ip, "63.217.16.24", "255.255.255.248" ) ||							// Tiffany Hong Kong - Times Square
		isInNet(public_ip, "63.218.57.192", "255.255.255.248" ) ||							// Tiffany Hong Kong - Peninsula
		isInNet(public_ip, "63.218.57.200", "255.255.255.248" ) ||							// Tiffany Hong Kong - Element
		isInNet(public_ip, "63.218.57.208", "255.255.255.248" ) ||							// Tiffany Hong Kong - Airport
		isInNet(public_ip, "63.221.158.40", "255.255.255.248" ) ||							// Tiffany Hong Kong - One Peking
		isInNet(public_ip, "207.226.140.208", "255.255.255.248" ) ||						// Tiffany Hong Kong - Harbour City
		isInNet(public_ip, "209.8.147.88", "255.255.255.248" ) ||							// Tiffany Hong Kong - Sogo
		isInNet(public_ip, "209.8.147.96", "255.255.255.248" ) ||							// Tiffany Hong Kong - IFC
		isInNet(public_ip, "209.8.147.104", "255.255.255.248" ) ||							// Tiffany Hong Kong - Pacific Place
		isInNet(public_ip, "209.9.219.18", "255.255.255.255")								// Workaround Tiffany Geoloc issue HK
		)
	return "PROXY hkg3.sme.zscloud.net:80; PROXY 147.161.192.47:80; DIRECT" ;
	/* END Hong Kong */

    /* Korea */
	if (
		isInNet(public_ip, "63.216.140.48", "255.255.255.248" ) ||							// Tiffany Korea - Bundang Hyundai Pangyo
		isInNet(public_ip, "63.216.140.96", "255.255.255.248" ) ||							// Tiffany Korea - Seoul Galleria (SE1ASPOSP01)
		isInNet(public_ip, "63.216.140.104", "255.255.255.248" ) ||							// Tiffany Korea - Seoul Hyundai Coex
		isInNet(public_ip, "63.216.140.112", "255.255.255.248" ) ||							// Tiffany Korea - Seoul Hyundai Apgujeong
		isInNet(public_ip, "63.216.140.120", "255.255.255.248" ) ||							// Tiffany Korea - Seoul Lotte Downtown
		isInNet(public_ip, "63.216.140.128", "255.255.255.248" ) ||							// Tiffany Korea - Seoul Lotte World Jamshil
		isInNet(public_ip, "63.216.140.136", "255.255.255.248" ) ||							// Tiffany Korea - Seoul Shinsegae Main Store
		isInNet(public_ip, "63.216.140.144", "255.255.255.248" ) ||							// Tiffany Korea - Seoul Shingsegae Gangnam
		isInNet(public_ip, "63.216.140.152", "255.255.255.248" ) ||							// Tiffany Korea - Seoul Shinsegae Hanam
		isInNet(public_ip, "63.216.140.160", "255.255.255.248" ) ||							// Tiffany Korea - Seoul Shinsegae YDP Store
		isInNet(public_ip, "63.216.164.0", "255.255.255.248" ) ||							// Tiffany Korea - Seoul TheHyundai (Parc1)
		isInNet(public_ip, "63.216.164.200", "255.255.255.248" ) ||							// Tiffany Korea - Seoul Shinsegae Daegu
		isInNet(public_ip, "63.216.164.224", "255.255.255.248" ) ||							// Tiffany Korea - Daejeon Galleria Timeworld
		isInNet(public_ip, "63.217.237.56", "255.255.255.248" ) ||							// Tiffany Korea - Busan Shinsegae Centum
		isInNet(public_ip, "63.218.237.40", "255.255.255.248" ) ||							// Tiffany Korea - Daegu Hyundai
		isInNet(public_ip, "63.218.237.48", "255.255.255.248" ) ||							// Tiffany Korea - Busan Lotte
		isInNet(public_ip, "63.218.237.72", "255.255.255.248")								// Workaround Tiffany Geoloc issue KOREA
		)
	return "PROXY sel1.sme.zscloud.net:80; PROXY 147.161.192.47:80; DIRECT" ;
	/* END Korea */
	
	/* Australia */
	if (
		isInNet(public_ip, "63.127.122.64", "255.255.255.248" ) ||							// Tiffany Australia - Brisbane Queens Plaza
		isInNet(public_ip, "63.217.122.16", "255.255.255.248" ) ||							// Tiffany Australia - Sydney - RITM0045484
        isInNet(public_ip, "63.217.120.96", "255.255.255.248" ) 			    			// Tiffany Australia - Perth - RITM0045484
		)
	return "PROXY syd3.sme.zscloud.net:80; PROXY 147.161.192.47:80; DIRECT" ;
	/* END Australia */
	
	/* New Zealand */
	if (
		isInNet(public_ip, "63.217.122.88", "255.255.255.248" ) 							// Tiffany New Zealand - Auckland Queens Street
		)
	return "PROXY akl2.sme.zscloud.net:80; PROXY 147.161.192.47:80; DIRECT" ;
	/* END New Zealand */
	
	/* Taiwan */
	if (
		isInNet(public_ip, "63.216.192.248", "255.255.255.248" ) ||							// Tiffany Taiwan - Taipei Mitsukoshi A9
		isInNet(public_ip, "63.222.40.248", "255.255.255.248" ) ||							// Tiffany Taiwan - Tainan Mitzukoshi
		isInNet(public_ip, "63.222.54.64", "255.255.255.248" ) ||							// Tiffany Taiwan - Taipei Sogo
		isInNet(public_ip, "63.222.54.88", "255.255.255.248" ) ||							// Tiffany Taiwan - Taipei Sogo BR4 Fuxing
		isInNet(public_ip, "205.252.18.240", "255.255.255.248" ) ||							// Tiffany Taiwan - Taipei 101
		isInNet(public_ip, "205.252.19.240", "255.255.255.248" ) ||							// Tiffany Taiwan - Taichung Far Eastern
		isInNet(public_ip, "205.252.19.248", "255.255.255.248" ) ||							// Tiffany Taiwan - Kaohsiung Hanshin
		isInNet(public_ip, "207.226.236.48", "255.255.255.248" ) 							// Tiffany Taiwan - Taipei Office
		)
	return "PROXY tep2.sme.zscloud.net:80; PROXY 147.161.192.47:80; DIRECT" ;
	/* END Taiwan */
	
	/* Malaysia, Singapore and Thailand */
	if (
		isInNet(public_ip, "205.252.169.8", "255.255.255.248" ) ||							// Tiffany Malaysia - Kuala Lumpur The Gardens Mall
		isInNet(public_ip, "205.252.169.16", "255.255.255.248" ) ||							// Tiffany Malaysia - Kuala Lumpur Office
		isInNet(public_ip, "205.252.169.24", "255.255.255.248" ) ||							// Tiffany Malaysia - Kuala Lumpur KLCC
		isInNet(public_ip, "205.252.169.32", "255.255.255.248" ) ||							// Tiffany Malaysia - Kuala Lumpur Pavilion
		isInNet(public_ip, "63.216.152.8", "255.255.255.248" ) ||							// Tiffany Singapore - Singapore Office
		isInNet(public_ip, "63.217.24.16", "255.255.255.248" ) ||							// Tiffany Singapore - Ngee Ann City
		isInNet(public_ip, "63.217.24.24", "255.255.255.248" ) ||							// Tiffany Singapore - Marina Bay Sands
		isInNet(public_ip, "63.217.24.32", "255.255.255.248" ) ||							// Tiffany Singapore - Changi Airport T3
		isInNet(public_ip, "63.217.59.224", "255.255.255.248" ) ||							// Tiffany Singapore - Orchard ION
		isInNet(public_ip, "63.217.61.48", "255.255.255.248" ) ||							// Tiffany Thailand - IconSiam
		isInNet(public_ip, "63.217.61.72", "255.255.255.248" ) ||							// Tiffany Thailand - Laurelton Gems (Thailand) Ltd (Head office)
		isInNet(public_ip, "63.218.171.120", "255.255.255.248" ) 							// Tiffany Thailand - Emporium
		)
	return "PROXY sin4.sme.zscloud.net:80; PROXY 147.161.192.47:80; DIRECT" ;
	/* END Malaysia & Singapore */
	
		/* INC0110871/INC011091 - Users in CDC CSC and HO redirect to NYC3 and WAS1 DC */
    if 	(
		(isInNet(User_Lan_IP, "10.152.164.0", "255.255.254.0")) ||
		(isInNet(User_Lan_IP, "10.152.187.0", "255.255.255.0")
	)
	) 

return "PROXY nyc3.sme.zscloud.net:80; PROXY was1.sme.zscloud.net:80; DIRECT";
    /* END INC0110871/INC011091 - Users in CDC CSC and HO redirect to NYC3 and WAS1 DC */
    
    /* RITM0081055 - Redirecting Standard chartered website to France DCs from Botswana */
    if (
        shExpMatch(country,"Botswana") 
        && 
        ( dnsDomainIs(host, "s2b.standardchartered.com") ||
          dnsDomainIs(host, "eljs.fa.us2.oraclecloud.com")      //RITM0081645
        )
        )  
    return "PROXY par2-2.sme.zscloud.net:80; PROXY mrs1.sme.zscloud.net:443; DIRECT";
    /* RITM0081055 - Redirecting Standard chartered website to France DCs from Botswana */


	
	
	/************************************************/
	/*												*/
	/* 		Specific Configuration for China  		*/
	/*												*/
	/************************************************/
		
	if (shExpMatch(country,"China"))
	{
	
		proxy_on = proxy_china;
		

		/* Redirect to Paris PZEN - China exceptions for LVMH Corporate ressources when users in LVMH Network */
		if 	(
			(InternalNetwork == "TRUE")
			&&
			(
			dnsDomainIs (host, "d2wy8f7a9ursnm.cloudfront.net") ||							// CDC - Security plugin for phishing in Outlook does not work in China
			dnsDomainIs (host, "concursolutions.com") ||
			dnsDomainIs (host, "code.jquery.com") ||										// CDC - Security plugin for phishing in Outlook does not work in China
			dnsDomainIs (host, "mrtedtalentlink.com") ||
			dnsDomainIs (host, "lvmhtalent.myetweb.com") ||
			dnsDomainIs (host, "addin-eu.securityeducation.com") ||							// CDC - Security plugin for phishing in Outlook does not work in China
			dnsDomainIs(host, "cn33.airwatchportals.com") ||                   				// WJI - INC0053445 - Airwatch portal doesn't work from China PZEN
			dnsDomainIs(host, "cn32.airwatchportals.com")                     				// WJI - INC0053445 - Airwatch portal doesn't work from China PZEN
	//		dnsDomainIs (host, "zoom.us") 													// INC0023368 Zoom can't be used in China
			)
			)
		return "PROXY emea-private-zscaler.proxy.lvmh:443; DIRECT";

		/* Redirect to Shanghai PZEN - China exceptions for LVMH Corporate ressources when users in LVMH Network */
		if 	(
			(InternalNetwork == "TRUE")
			&&
			(
			dnsDomainIs(host, "90264347-test-retail-ondemand.cegid-cloud.cn") || 			// Test pod Cegid CN for W&J
			dnsDomainIs(host, "90373904-test-retail-ondemand.cegid-cloud.cn") || 			// Test pod Cegid CN for W&J
			dnsDomainIs(host, "90264347-retail-ondemand.cegid-cloud.cn") || 				// Production pod Cegid CN for W&J
			dnsDomainIs(host, "90373904-retail-ondemand.cegid-cloud.cn") || 				// Production pod Cegid CN for W&J
			dnsDomainIs(host, "hosting.fluidbook.com") || 									// RITM0029550_20210107_RAD
		  //dnsDomainIs(host, "qualiving.lvmh.com") || 										// RITM0029699_20210122_RAD
			dnsDomainIs(host, "gaiacloud.com") || // INC0080083
            dnsDomainIs(host, "gaiaworkforce.com") || // INC0080083
			dnsDomainIs(host, "moet-hennessy.atlassian.net") 	||							// CHG0046840_20240103_VP_1NET
			dnsDomainIs(host, "tiffany.printercloud.com")  ||	                   // RITM0087547
			dnsDomainIs(host, "tiffany.jamfcloud.com")     ||                      // RITM0092062
			dnsDomainIs(host, "uipath.com") 	||						                    // RITM0067323
			dnsDomainIs(host, "account.uipath.com") 	||						            // RITM0067323
			dnsDomainIs(host, "cloud.uipath.com")       ||	 						            // RITM0067323
			dnsDomainIs(host, "tiffany.service-now.com")                                    // RITM0093358
			)
			)
		return "PROXY auth-china-private-zscaler.proxy.lvmh:443; PROXY 10.104.248.251:443; DIRECT";	
		
  
		/* Redirection to exposed Shanghai PZEN not in Plaza 66 and assimilated */
		if (
			(P66Network == "FALSE")
			&&
			(
			dnsDomainIs(host, ".salesforce.com") ||
			dnsDomainIs(host, ".office.com") ||
			dnsDomainIs(host, ".office365.com") ||
            dnsDomainIs(host, ".office.net") ||
            dnsDomainIs(host, ".outlook.com") ||
            dnsDomainIs(host, ".onmicrosoft.com") ||
            dnsDomainIs(host, ".sharepoint.com") ||
            dnsDomainIs(host, ".microsoft.com") ||
            dnsDomainIs(host, ".azure.net") ||
            dnsDomainIs(host, ".powerbi.com") ||                							// INC0056891
            dnsDomainIs(host, ".powerapps.com") ||              							// INC0056891
            dnsDomainIs(host, ".skypeforbusiness.com") ||
            dnsDomainIs(host, ".microsoftstream.com") ||
            dnsDomainIs(host, ".live.com") ||
            dnsDomainIs(host, ".microsoftonline.com") ||
            dnsDomainIs(host, ".windows.net") ||
            dnsDomainIs(host, ".alicdn.com") ||
            dnsDomainIs(host, ".taobao.com") ||
            dnsDomainIs(host, ".tmall.com") ||
            dnsDomainIs(host, ".microsoftusercontent.com") ||						   
			dnsDomainIs(host, "mydigitalworkplace.lvmh.com") ||
			dnsDomainIs(host, "zoom.us")  ||                                            	// RITM0044927
			dnsDomainIs(host, "github.com") ||                                           	// RITM0053132    
            dnsDomainIs(host, "githubapp.com") ||    										// RITM0053132
            dnsDomainIs(host, ".blob.core.windows.net") ||                              	// RITM0053132																				  															  
            dnsDomainIs(host, ".githubusercontent.com") ||                              	// RITM0053132
			dnsDomainIs(host,"githubassets.com") ||                                      	// RITM0053132
            dnsDomainIs(host, "ghcr.io")   ||                                              	// RITM0053132
            dnsDomainIs(host, "allmyit.sephora.asia") ||
			shExpMatch(host, "www.moynat.com")                                       		// RITM0054441																						  																														  
			)
			)
		return "PROXY 103.204.73.226:9400; PROXY 140.210.152.47:9400; DIRECT";	
		/* Redirection to exposed Shanghai PZEN not in Plaza 66 and assimilated */
	}	
	
     if (
        (
        (isInNet(myIpAddress(), "10.201.64.0", "255.255.248.0"))
         )
        &&
        (
        (dnsDomainIs(host,"wxapp.tc.qq.com"))  ||    
        (shExpMatch(host, "wxapp.tc.qq.com"))  ||
    	(dnsDomainIs(host,".qq.com"))	       ||    
        (shExpMatch(host, ".qq.com"))  ||
		(isInNet(host, "182.254.116.0", "255.255.255.0")) ||
		(isInNet(host, "182.254.118.0", "255.255.255.0")) ||
		(dnsDomainIs(host,".weixinbridge.com"))	       ||    
        (shExpMatch(host, ".weixinbridge.com"))  ||
		(dnsDomainIs(host,".servicewechat.com"))	       ||    
        (shExpMatch(host, ".servicewechat.com"))  ||
		(dnsDomainIs(host,".qlogo.cn"))	       ||    
        (shExpMatch(host, ".qlogo.cn"))        ||
        (shExpMatch(host, ".qpic.cn"))  ||
        (dnsDomainIs(host,"tiffanyandco.app.box.com"))	       ||    
        (shExpMatch(host, "tiffanyandco.app.box.com"))        ||
		(dnsDomainIs(host,".qpic.cn"))	       
        )
        )
	return "PROXY sha2.sme.zscaler.net:443; PROXY bjs3.sme.zscloud.net:443; DIRECT";
	
	
if (
		(isInNet(myIpAddress(), "10.201.64.0", "255.255.248.0"))    	
   )
return "PROXY 103.204.73.226:9400; PROXY 140.210.152.47:9400; DIRECT";
	
//	       	if (
//		(isInNet(myIpAddress(), "10.201.64.0", "255.255.248.0"))    	
//		)
//return "PROXY auth-china-private-zscaler.proxy.lvmh:443; PROXY 140.210.152.47:9400; DIRECT";	
	
	/* Users in Plaza66 and assimilated use Shanghai PZEN */
	if (P66Network == "TRUE")
	return "PROXY auth-china-private-zscaler.proxy.lvmh:443; PROXY 10.104.248.251:443; PROXY 140.210.152.47:9400; DIRECT";
	/* END Users in Plaza66 and assimilated use Shanghai PZEN */		
	
		
    
	/************************************************/
	/*												*/
	/* 		Default action: send to closest ZEN  	*/
	/*												*/
	/************************************************/
	
	return proxy_on;
}
