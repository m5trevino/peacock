#!/bin/bash

while read line; do
  ID=$(echo $line | cut -d'|' -f1)
  TEXT=$(echo $line | cut -d'|' -f2)

  echo "Sentence $ID: $TEXT"
  echo "Recording: dataset/wavs/$ID.wav (2s silence or 10s max)..."

  # Record at 16kHz mono, stop on 2s silence or at 10s
  rec -r 16000 -c 1 -b 16 dataset/wavs/$ID.wav silence 1 0.1 1% 1 2.0 1% trim 0 10

  echo "Finished recording Sentence $ID. Press Enter for next..."
  read
done < dataset/metadata.csv
