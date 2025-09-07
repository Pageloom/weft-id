On a dev environment - this folder is mapped to the docker-entrypoint-initdb.d in the 
postgres container. Any .sql or .sh files placed here will be executed on the first (and only the first) 
container startup. It can be rerun only if the dbdata volume is removed.
