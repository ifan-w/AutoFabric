#! /bin/sh
if [ "$1" = "-h" ]
then
    echo 'run.sh <command> <config_file> <updated_config_file>'
else
    rm output.temp
    python3 main.py -c $1 -C $2 -U $3 >> output.temp

    cat output.temp | while read line
    do
        # echo $line >> 'output'
        echo '>>>>>--------------------------------------------------'
        echo $line
        $line
        echo '<<<<<--------------------------------------------------'
    done
    rm output.temp
fi


