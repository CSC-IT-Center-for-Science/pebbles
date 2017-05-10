FROM nginx

MAINTAINER CSCfi Notebook Team <notebooks@postit.csc.fi>

RUN apt update && apt install inotify-tools -y && apt clean

COPY watch_and_reload_nginx.sh /usr/local/bin/watch_and_reload_nginx.sh
RUN chmod a+x  /usr/local/bin/watch_and_reload_nginx.sh






