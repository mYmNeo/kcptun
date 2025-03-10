package gfwlist

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var GFWListURL = "https://gitlab.com/gfwlist/gfwlist/raw/master/gfwlist.txt"

type hostWildcardRule struct {
	pattern string
}

func (r *hostWildcardRule) match(domain string) bool {
	return strings.Contains(domain, r.pattern)
}

type urlWildcardRule struct {
	pattern     string
	prefixMatch bool
}

func (r *urlWildcardRule) match(domain string) bool {
	if r.prefixMatch {
		return strings.HasPrefix(domain, r.pattern)
	}
	return strings.Contains(domain, r.pattern)
}

type regexRule struct {
	pattern string
}

func (r *regexRule) match(domain string) bool {
	matched, err := regexp.MatchString(r.pattern, domain)
	if err != nil {
		slog.Error("Invalid regex patterns", "patterns", r.pattern, "error", err)
	}
	return matched
}

type whiteListRule struct {
	r gfwListRule
}

func (r *whiteListRule) match(domain string) bool {
	return r.r.match(domain)
}

type gfwListRule interface {
	match(domain string) bool
}

type GFWList struct {
	ruleMap  map[string]gfwListRule
	ruleList []gfwListRule
}

func (gfw *GFWList) FastMatchDomain(domain string) (bool, bool) {
	if gfw.ruleMap == nil || len(domain) == 0 {
		return false, false
	}

	rootDomain := domain
	if strings.Contains(domain, ":") {
		domain, _, _ = net.SplitHostPort(domain)
		rootDomain = domain
	}

	rule, exist := gfw.ruleMap[domain]
	if !exist {
		ss := strings.Split(domain, ".")
		if len(ss) > 2 {
			rootDomain = ss[len(ss)-2] + "." + ss[len(ss)-1]
			if len(ss[len(ss)-2]) < 4 && len(ss) >= 3 {
				rootDomain = ss[len(ss)-3] + "." + rootDomain
			}
		}
		if rootDomain != domain {
			rule, exist = gfw.ruleMap[rootDomain]
		}
	}
	if exist {
		matched := rule.match(domain)
		if _, ok := rule.(*whiteListRule); ok {
			return !matched, true
		}
		return matched, true
	}
	return false, false
}

func (gfw *GFWList) IsBlockedByGFW(domain string) bool {
	fastMatchResult, exist := gfw.FastMatchDomain(domain)
	if exist {
		return fastMatchResult
	}

	for _, rule := range gfw.ruleList {
		if rule.match(domain) {
			if _, ok := rule.(*whiteListRule); ok {
				return false
			}
			return true
		}
	}
	return false
}

func Parse(rules string) (*GFWList, error) {
	reader := bufio.NewReader(strings.NewReader(rules))
	gfw := new(GFWList)
	gfw.ruleMap = make(map[string]gfwListRule)
	//i := 0
	for {
		line, _, err := reader.ReadLine()
		if nil != err {
			break
		}
		str := strings.TrimSpace(string(line))
		//comment
		if strings.HasPrefix(str, "!") || len(str) == 0 || strings.HasPrefix(str, "[") {
			continue
		}
		var rule gfwListRule
		isWhileListRule := false
		fastMatch := false
		if strings.HasPrefix(str, "@@") {
			str = str[2:]
			isWhileListRule = true
		}
		if strings.HasPrefix(str, "/") && strings.HasSuffix(str, "/") {
			str = str[1 : len(str)-1]
			rule = &regexRule{str}
		} else {
			if strings.HasPrefix(str, "||") {
				fastMatch = true
				str = str[2:]
				rule = &hostWildcardRule{str}
			} else if strings.HasPrefix(str, "|") {
				rule = &urlWildcardRule{str[1:], true}
			} else {
				if !strings.Contains(str, "/") {
					fastMatch = true
					str = strings.TrimPrefix(str, ".")
					rule = &hostWildcardRule{str}
				} else {
					rule = &urlWildcardRule{str, false}
				}
			}
		}
		if isWhileListRule {
			rule = &whiteListRule{rule}
		}
		if fastMatch {
			gfw.ruleMap[str] = rule
		}
	}
	return gfw, nil
}

func NewGFWList(urls []string, localFiles []string) (*GFWList, error) {
	var (
		readers []io.Reader
	)

	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("failed to get gfwlist: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to get gfwlist: %v", resp.Status)
		}

		readers = append(readers, resp.Body)
	}

	for _, localFile := range localFiles {
		localReader, err := os.Open(localFile)
		if err != nil {
			return nil, fmt.Errorf("failed to write gfwlist to local file: %v", err)
		}

		readers = append(readers, localReader)
	}

	gfwListData, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, io.MultiReader(readers...)))
	if err != nil {
		return nil, fmt.Errorf("failed to read gfwlist: %v", err)
	}

	return Parse(string(gfwListData))
}
