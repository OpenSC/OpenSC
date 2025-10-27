if [ ! $# -eq 3 ]; then
    echo "Usage: template description.1.xml generated_completion"
    exit 1
fi
if [ ! -r "$1" ]; then
    echo "The file \"$1\" does not exist or is not readable"
    exit 2
fi
if [ ! -r "$2" ]; then
    echo "The file \"$2\" does not exist or is not readable"
    exit 3
fi

ALLOPTS=$(sed -n 's,.*<option>\([^<]*\)</option>.*,\1,pg' "$2" | sort -u | grep '^-' | tr '\n' ' ')

OPTSWITHARGS=$(sed -n 's,.*<option>\([^<]*\)</option>.*<replaceable>.*,\1,pg' "$2" | sort -u | grep '^-' | tr '\n' '|' | sed 's,|$$,,' | grep ^ || echo "!*")

FILEOPTS=$(sed -n 's,.*<option>\([^<]*\)</option>.*<replaceable>.*filename.*,\1,pg' "$2" | sort -u | grep '^-' | tr '\n' '|' | sed 's,|$$,,' | grep ^ || echo "!*")

PINOPTS=$(sed -En 's,.*<option>([^<]*)</option>.*<replaceable>\s*(newpin|pin|puk|sopin|sopuk)\s*<.*,\1,pg' "$2" | sort -u | grep '^-' | tr '\n' '|' | sed 's,|$$,,' | grep ^ || echo "!*")

MODULEOPTS=$(sed -n 's,.*<option>\([^<]*\)</option>.*<replaceable>.*mod.*,\1,pg' "$2" | sort -u | grep '^-' | tr '\n' '|' | sed 's,|$$,,' | grep ^ || echo "!*")

FUNCTION_NAME=$(basename "$3" | sed s,-,_,g)

PROGRAM_NAME=$(basename "$3")

cat "$1" \
    | sed "s,ALLOPTS,${ALLOPTS}," \
    | sed "s,OPTSWITHARGS,${OPTSWITHARGS}," \
    | sed "s,FILEOPTS,${FILEOPTS},"  \
    | sed "s,PINOPTS,${PINOPTS},"  \
    | sed "s,MODULEOPTS,${MODULEOPTS}," \
    | sed "s,FUNCTION_NAME,${FUNCTION_NAME}," \
    | sed "s,PROGRAM_NAME,${PROGRAM_NAME}," \
> "$3"

exit 0
