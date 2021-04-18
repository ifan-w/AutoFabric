#! /bin/sh
python3 main.py -c initnode -C config.yaml -U config.new.yaml >> output.temp

cat output.temp | while read line
do
    # echo $line >> 'output'
    echo ------------------------------
    echo $line
    echo ------------------------------
    `$line`
done

rm output.temp

