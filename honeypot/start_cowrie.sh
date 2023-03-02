DIR="log"
if [ -d "$DIR" ]; then
  # Take action if $DIR exists. #
  COWRIE_LOGS=`date '+%Y-%m-%d-%H:%M'`
  echo "Saving current logs to $COWRIE_LOGS..."
  mkdir $COWRIE_LOGS
  cp -R $DIR/ $COWRIE_LOGS/
fi

rm -rf $DIR/*
docker-compose up cowrie