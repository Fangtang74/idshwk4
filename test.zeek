@load base/frameworks/sumstats

event http_reply(c: connection, version: string, code: count, reason: string) {
    SumStats::observe("response", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
    if (code == 404) {
        SumStats::observe("response404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
        SumStats::observe("responseUnique404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
    }
}

event zeek_init() {
    local r_all_response = SumStats::Reducer($stream="response", $apply=set(SumStats::SUM));
    local r_404_response = SumStats::Reducer($stream="response404", $apply=set(SumStats::SUM));
    local r_unique404_response = SumStats::Reducer($stream="responseUnique404", $apply=set(SumStats::UNIQUE));

    SumStats::create([$name="detect http scan", $epoch=10min, $reducers=set(r_all_response, r_404_response,r_unique404_response), $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
        local r1 = result["response"];
        local r2 = result["response404"];
        local r3 = result["responseUnique404"];
        if (r2$sum > 2) {
            if (r2$sum / r1$sum > 0.2) {
                if (r3$unique / r2$sum > 0.5) {
                    print fmt(" %s is a scanner with %.0f scan attemps on %d urls", key$host, r2$sum, r3$unique);
                } 
            }
        }
    }]);
}
