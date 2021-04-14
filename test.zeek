@load base/protocols/conn
@load base/protocols/http

global ip_statistic: table[addr] of table[string] of count; 
global ip_404_sets: table[addr] of set[string]; 
global ip_time: table[addr] of time;  
global ip_interval: interval = 10min;

global analyse: function(ip: addr);

event http_begin_entity(c: connection, is_orig: bool)
{
	if (is_orig && c$id$orig_h !in ip_time)
	{
		ip_time[c$id$orig_h] = network_time();
		ip_statistic[c$id$orig_h] = table(
						  ["all_response"] = 0,
						  ["404_response"] = 0
						 );
		ip_404_sets[c$id$orig_h] = set();
	}	
}


event http_reply(c: connection, version: string, code: count, reason: string)
{
	++ ip_statistic[c$id$orig_h]["all_response"];
	
	if (code == 404)
	{
		++ ip_statistic[c$id$orig_h]["404_response"];
        	add ip_404_sets[c$id$orig_h][c$http$host + c$http$uri];
	}
    	
	for (ip, time_record in ip_time)
	{
		if (network_time() - time_record  >= ip_interval)
		{
			analyse[ip];
			ip_time[ip] = network_time();
			ip_statistic[ip]["all_responses"] = 0;
			ip_statistic[ip]["404_responses"] = 0;
			ip_404_sets[ip] = set();
		}
	}
	
}


function analyse(ip: addr)
{
	if (ip_statistic[ip]["404_response"] > 2 && ip_statistic[ip]["404_response"] > 0.2 * ip_statistic[ip]["all_response"] && |ip_404_sets[ip]| > 0.5 * ip_statistic[ip]["404_response"])
	{
		print fmt("%s is a scanner with %s attemps on %s urls", ip, ip_statistic[ip]["404_response"], |ip_404_sets[ip]|);
	}

}
