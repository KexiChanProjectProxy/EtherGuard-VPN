package path

import (
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	orderedmap "github.com/KusakabeSi/EtherGuard-VPN/orderdmap"
	"github.com/beevik/ntp"
)

var forever = time.Hour * 99999

func (g *IG) InitNTP() {
	g.ntp_init_t = time.Now()
	if g.ntp_info.UseNTP {
		if len(g.ntp_info.Servers) == 0 {
			g.ntp_info.UseNTP = false
			return
		}
		g.ntp_servers = *orderedmap.New()
		for _, url := range g.ntp_info.Servers {
			g.ntp_servers.Set(url, ntp.Response{
				RTT: forever,
			})
		}
		g.SyncTimeMultiple(-1)
		go g.RoutineSyncTime()
	} else {
		if g.loglevel.LogNTP {
			fmt.Println("NTP: NTP sync disabled")
		}
	}
}

func (g *IG) RoutineSyncTime() {
	if !g.ntp_info.UseNTP {
		return
	}
	for {
		if g.ntpProgress.enabled.Get() {
			atomic.StoreInt64(&g.ntpProgress.lastRoutineWakeAt, time.Now().UnixNano())
			atomic.StoreInt64(&g.ntpProgress.routineSleepSince, 0)
		}
		g.SyncTimeMultiple(g.ntp_info.MaxServerUse)
		if g.ntpProgress.enabled.Get() {
			atomic.StoreInt64(&g.ntpProgress.routineSleepSince, time.Now().UnixNano())
		}
		time.Sleep(mtypes.S2TD(g.ntp_info.SyncTimeInterval))
	}
}

type ByDuration []time.Duration

func (a ByDuration) Len() int           { return len(a) }
func (a ByDuration) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByDuration) Less(i, j int) bool { return a[i] < a[j] }

func (g *IG) SyncTimeMultiple(count int) {
	if g.ntpProgress.enabled.Get() {
		now := time.Now()
		atomic.StoreInt64(&g.ntpProgress.lastCycleStart, now.UnixNano())
		atomic.StoreInt64(&g.ntpProgress.cycleWaitSince, now.UnixNano())
	}
	var url2sync []string
	if count < 0 {
		count = len(g.ntp_servers.Keys())
	}
	if count > len(g.ntp_servers.Keys()) {
		count = len(g.ntp_servers.Keys())
	}
	for index, url := range g.ntp_servers.Keys() {
		if index < count {
			url2sync = append(url2sync, url)
		} else {
			break
		}
	}
	for _, url := range url2sync {
		g.ntp_wg.Add(1)
		if g.ntpProgress.enabled.Get() {
			atomic.AddInt64(&g.ntpProgress.inFlight, 1)
		}
		go g.SyncTime(url, mtypes.S2TD(g.ntp_info.NTPTimeout))
	}
	if g.ntpProgress.enabled.Get() {
		atomic.StoreInt64(&g.ntpProgress.lastCycleCount, int64(len(url2sync)))
	}
	g.ntp_wg.Wait()
	if g.ntpProgress.enabled.Get() {
		atomic.StoreInt64(&g.ntpProgress.cycleWaitSince, 0)
		atomic.StoreInt64(&g.ntpProgress.lastCycleDone, time.Now().UnixNano())
	}
	g.ntp_servers.Sort(func(a *orderedmap.Pair, b *orderedmap.Pair) bool {
		return a.Value().(ntp.Response).RTT < b.Value().(ntp.Response).RTT
	})
	results := make([]time.Duration, 0, count)
	for index, url := range g.ntp_servers.Keys() {
		val, has := g.ntp_servers.Get(url)
		if !has {
			continue
		}
		if index >= count {
			break
		}
		result := val.(ntp.Response)
		if result.RTT < forever {
			results = append(results, result.ClockOffset)
		}
	}
	if g.loglevel.LogNTP {
		fmt.Println("NTP: All done")
	}
	sort.Sort(ByDuration(results))
	if len(results) > 3 {
		results = results[1 : len(results)-1]
	}
	var totaltime time.Duration
	for _, result := range results {
		totaltime += result
	}
	if len(results) > 0 {
		avgtime := totaltime / time.Duration(len(results))
		if g.loglevel.LogNTP {
			fmt.Println("NTP: Arvage offset: " + avgtime.String())
		}
		g.ntp_offset = avgtime
	} else {
		if g.loglevel.LogNTP {
			fmt.Println("NTP: All server failed, skip sync")
		}
	}

}

func (g *IG) SyncTime(url string, timeout time.Duration) {
	if g.ntpProgress.enabled.Get() {
		atomic.StoreInt64(&g.ntpProgress.lastQueryStart, time.Now().UnixNano())
	}
	if g.loglevel.LogNTP {
		fmt.Println("NTP: Starting syncing with NTP server :" + url)
	}
	options := ntp.QueryOptions{Timeout: timeout}
	response, err := ntp.QueryWithOptions(url, options)
	if g.ntpProgress.enabled.Get() {
		now := time.Now().UnixNano()
		atomic.StoreInt64(&g.ntpProgress.lastQueryDone, now)
		atomic.AddInt64(&g.ntpProgress.inFlight, -1)
	}
	if err == nil {
		if g.ntpProgress.enabled.Get() {
			atomic.StoreInt64(&g.ntpProgress.lastSuccessAt, time.Now().UnixNano())
			atomic.StoreInt64(&g.ntpProgress.lastQueryRTT, response.RTT.Nanoseconds())
			atomic.StoreInt64(&g.ntpProgress.lastQueryOffset, response.ClockOffset.Nanoseconds())
		}
		if g.loglevel.LogNTP {
			fmt.Println("NTP:  NTP server :" + url + "\tResult:" + response.ClockOffset.String() + " RTT:" + response.RTT.String())
		}
		g.ntp_servers.Set(url, *response)
	} else {
		if g.ntpProgress.enabled.Get() {
			atomic.StoreInt64(&g.ntpProgress.lastFailureAt, time.Now().UnixNano())
			atomic.StoreInt64(&g.ntpProgress.lastQueryError, time.Since(g.ntp_init_t).Nanoseconds())
		}
		if g.loglevel.LogNTP {
			fmt.Println("NTP:  NTP server :" + url + "\tFailed :" + err.Error())
		}
		g.ntp_servers.Set(url, ntp.Response{
			RTT: forever + time.Since(g.ntp_init_t),
		})
	}
	g.ntp_wg.Done()
}
