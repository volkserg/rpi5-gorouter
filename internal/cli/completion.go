package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/lists"
)

// Completion печатает скрипт автодополнения rsc и router_service_ctl для shell
// (bash или zsh). Список команд берётся из той же таблицы, что и справка,
// поэтому дополнение не расходится с бинарником.
func Completion(w io.Writer, shell string) error {
	var names, described []string
	flags := map[string]string{}
	for _, c := range commands {
		if c.name == "" {
			continue
		}
		names = append(names, c.name)
		described = append(described, fmt.Sprintf("'%s:%s'", c.name, c.help))
		if strings.HasPrefix(c.args, "[--") {
			flags[c.name] = strings.ReplaceAll(strings.Trim(c.args, "[]"), "|", " ")
		}
	}
	names = append(names, "help")
	described = append(described, "'help:Показать справку'")
	file := config.DefaultDir + "/" + lists.VPNFileName

	var flagCases strings.Builder
	for _, c := range commands {
		if f, ok := flags[c.name]; ok {
			fmt.Fprintf(&flagCases, "        %s) words_=(%s) ;;\n", c.name, f)
		}
	}

	switch shell {
	case "bash":
		_, err := fmt.Fprintf(w, bashCompletion, strings.Join(names, " "), file, flagCases.String())
		return err
	case "zsh":
		_, err := fmt.Fprintf(w, zshCompletion, strings.Join(described, "\n        "), file, flagCases.String())
		return err
	}
	return fmt.Errorf("неизвестная оболочка %q (bash или zsh)", shell)
}

// Записи списка для remove-*: домены — строки не с цифры, IP/CIDR — с цифры.
// Каталог конфигов можно переопределить ROUTERD_CONFIG_DIR, как и для CLI.

const bashCompletion = `# bash completion для rsc и router_service_ctl (сгенерировано: routerd completion bash)

_router_service_ctl_entries() {
    local file="${ROUTERD_CONFIG_DIR:+${ROUTERD_CONFIG_DIR}/vpn_domains.txt}"
    file="${file:-%[2]s}"
    [[ -r "$file" ]] || return
    local line
    while IFS= read -r line; do
        line="${line%%%%#*}"; line="${line//[[:space:]]/}"
        [[ -z "$line" ]] && continue
        if [[ "$1" == ip && "$line" == [0-9]* ]] || [[ "$1" == domain && "$line" != [0-9]* ]]; then
            printf '%%s\n' "$line"
        fi
    done <"$file"
}

_router_service_ctl() {
    local cur="${COMP_WORDS[COMP_CWORD]}" words_=()
    if ((COMP_CWORD == 1)); then
        COMPREPLY=($(compgen -W "%[1]s" -- "$cur"))
        return
    fi
    ((COMP_CWORD == 2)) || return
    case "${COMP_WORDS[1]}" in
        remove-vpn-domain) words_=($(_router_service_ctl_entries domain)) ;;
        remove-vpn-ip) words_=($(_router_service_ctl_entries ip)) ;;
        load-vpn-domains | load-vpn-ips)
            compopt -o filenames 2>/dev/null
            COMPREPLY=($(compgen -f -- "$cur"))
            return
            ;;
%[3]s    esac
    COMPREPLY=($(compgen -W "${words_[*]}" -- "$cur"))
}

complete -F _router_service_ctl rsc router_service_ctl
`

const zshCompletion = `#compdef rsc router_service_ctl
# zsh completion для rsc и router_service_ctl (сгенерировано: routerd completion zsh)

_router_service_ctl_entries() {
    local file=${ROUTERD_CONFIG_DIR:+$ROUTERD_CONFIG_DIR/vpn_domains.txt}
    file=${file:-%[2]s}
    [[ -r $file ]] || return
    local line
    for line in "${(@f)$(<$file)}"; do
        line=${line%%%%\#*}; line=${line//[[:space:]]/}
        [[ -z $line ]] && continue
        if [[ $1 == ip && $line == [0-9]* ]] || [[ $1 == domain && $line != [0-9]* ]]; then
            print -r -- $line
        fi
    done
}

_router_service_ctl() {
    local -a commands words_
    commands=(
        %[1]s
    )
    if (( CURRENT == 2 )); then
        _describe -t commands 'команда' commands
        return
    fi
    (( CURRENT == 3 )) || return
    case $words[2] in
        remove-vpn-domain) words_=(${(f)"$(_router_service_ctl_entries domain)"}) ;;
        remove-vpn-ip) words_=(${(f)"$(_router_service_ctl_entries ip)"}) ;;
        load-vpn-domains | load-vpn-ips) _files; return ;;
%[3]s    esac
    (( ${#words_} )) && compadd -a words_
}

_router_service_ctl "$@"
`
