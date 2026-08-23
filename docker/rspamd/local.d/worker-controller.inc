# Sentio OSS quickstart - Rspamd controller (Bayes training + admin UI).
# Only reachable on the docker network. Set a password before exposing to the
# host or the internet.
bind_socket = "*:11334";
# password = "$2$..."; # generate with `rspamadm pw`
# enable_password = "$2$...";
