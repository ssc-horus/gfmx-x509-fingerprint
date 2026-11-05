package gfmx

import (
	"fmt"
	"strconv"
	"sync"
)

// civil is a calendar time in UTC with second resolution (fractions are ignored,
// as in the reference implementation).
type civil struct {
	year, month, day, hour, min, sec int
}

// daysFromCivil returns days since 1970-01-01 in the proleptic Gregorian calendar.
func daysFromCivil(y, m, d int) int64 {
	if m <= 2 {
		y--
	}
	era := y / 400
	if y < 0 && y%400 != 0 {
		era--
	}
	yoe := y - era*400
	mp := (m + 9) % 12
	doy := (153*mp+2)/5 + d - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return int64(era)*146097 + int64(doe) - 719468
}

func isLeap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }

func daysIn(y, m int) int {
	switch m {
	case 2:
		if isLeap(y) {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

func (c civil) unix() int64 {
	return daysFromCivil(c.year, c.month, c.day)*86400 + int64(c.hour*3600+c.min*60+c.sec)
}

// valid mirrors the range checks of Python's datetime constructor.
func (c civil) valid() bool {
	return c.year >= 1 && c.year <= 9999 && c.month >= 1 && c.month <= 12 &&
		c.day >= 1 && c.day <= daysIn(c.year, c.month) && c.hour <= 23 && c.min <= 59 && c.sec <= 59
}

func digits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func atoi2(b []byte) int { n, _ := strconv.Atoi(string(b)); return n }

// parseTime returns (time, kind 'U'|'G'|'?', standard format, ok-to-use).
func parseTime(t *tlv) (civil, byte, bool, bool) {
	s := t.content
	if isUniversal(t, 23) { // UTCTime: YYMMDDhhmm[ss]Z
		std := len(s) == 13 && s[12] == 'Z' && digits(s[:12])
		if !(len(s) == 11 || len(s) == 13) || s[len(s)-1] != 'Z' || !digits(s[:len(s)-1]) {
			return civil{}, 'U', false, false
		}
		yy := atoi2(s[0:2])
		year := 2000 + yy
		if yy >= 50 {
			year = 1900 + yy
		}
		c := civil{year, atoi2(s[2:4]), atoi2(s[4:6]), atoi2(s[6:8]), atoi2(s[8:10]), 0}
		if len(s) == 13 {
			c.sec = atoi2(s[10:12])
		}
		if !c.valid() {
			return civil{}, 'U', false, false
		}
		return c, 'U', std, true
	}
	if isUniversal(t, 24) { // GeneralizedTime: YYYYMMDDhhmm[ss][.f+]Z
		std := len(s) == 15 && s[14] == 'Z' && digits(s[:14])
		if len(s) < 13 || s[len(s)-1] != 'Z' || !digits(s[:12]) {
			return civil{}, 'G', false, false
		}
		rest := s[12 : len(s)-1]
		sec := 0
		if len(rest) >= 2 && digits(rest[:2]) {
			sec = atoi2(rest[:2])
			rest = rest[2:]
		}
		if len(rest) > 0 && !(rest[0] == '.' && len(rest) >= 2 && digits(rest[1:])) {
			return civil{}, 'G', false, false
		}
		c := civil{atoi2(s[0:4]), atoi2(s[4:6]), atoi2(s[6:8]), atoi2(s[8:10]), atoi2(s[10:12]), sec}
		if !c.valid() {
			return civil{}, 'G', false, false
		}
		return c, 'G', std, true
	}
	return civil{}, '?', false, false
}

// ---- SPAN: length + kind ----

var calCache sync.Map // months -> [2]int64

// calendarDays: fewest and most days that `months` calendar months can span over every
// start date in a 400-year Gregorian cycle and both month-end conventions (clamp and
// roll-over). Day-of-month 1..28 all behave like 1.
func calendarDays(months int) (int64, int64) {
	if v, ok := calCache.Load(months); ok {
		r := v.([2]int64)
		return r[0], r[1]
	}
	lo, hi := int64(1<<62), int64(-1<<62)
	for y := 2000; y < 2400; y++ {
		for m := 1; m <= 12; m++ {
			k := m - 1 + months
			yy, mm := y+k/12, k%12+1
			first := daysFromCivil(yy, mm, 1)
			tdim := daysIn(yy, mm)
			for _, d := range [4]int{1, 29, 30, 31} {
				if d > daysIn(y, m) {
					continue
				}
				start := daysFromCivil(y, m, d)
				cl := d
				if tdim < cl {
					cl = tdim
				}
				for _, end := range [2]int64{first + int64(cl) - 1, first + int64(d) - 1} {
					span := end - start
					if span < lo {
						lo = span
					}
					if span > hi {
						hi = span
					}
				}
			}
		}
	}
	calCache.Store(months, [2]int64{lo, hi})
	return lo, hi
}

func isoMonths(n int) string {
	y, m := n/12, n%12
	s := "P"
	if y != 0 {
		s += strconv.Itoa(y) + "Y"
	}
	if m != 0 {
		s += strconv.Itoa(m) + "M"
	}
	return s
}

const avgMonthDays = 146097.0 / 4800.0

func spanLength(nb, na civil) (string, string) {
	if na.year == 9999 && na.month == 12 && na.day == 31 {
		return "-", "end9999"
	}
	if na == (civil{2049, 12, 31, 23, 59, 59}) {
		return "-", "end2049"
	}
	if na == (civil{2038, 1, 19, 3, 14, 7}) {
		return "-", "end2038"
	}
	dur := na.unix() - nb.unix()
	switch {
	case dur < 0:
		return "-", "neg"
	case dur < 60:
		return fmt.Sprintf("PT%dS", dur), "exact"
	case dur < 3570:
		return fmt.Sprintf("PT%dM", (dur+30)/60), "exact"
	case dur < 2*86400:
		return fmt.Sprintf("PT%dH", (dur+1800)/3600), "exact"
	}
	days := (dur + 43200) / 86400 // nearest day, half up
	if days >= 28 && days <= 2_000_000 {
		n0 := int(float64(days)/avgMonthDays + 0.5)
		for n := n0 - 1; n <= n0+1; n++ {
			if n >= 1 {
				lo, hi := calendarDays(n)
				if lo <= days && days <= hi {
					return isoMonths(n), "cal"
				}
			}
		}
	}
	return fmt.Sprintf("P%dD", days), "exact"
}

func spanText(nb, na civil) string {
	s := na.unix() - nb.unix()
	if s < 0 {
		return "neg"
	}
	d := s / 86400
	s %= 86400
	return fmt.Sprintf("%dd%02d:%02d:%02d", d, s/3600, s%3600/60, s%60)
}
