job "depictor-live" {
  datacenters = ["ator-fin"]
  type        = "service"
  namespace   = "live-network"

  constraint {
    attribute = "${meta.pool}"
    value = "live-network"
  }

  group "depictor" {
    count = 1

    network {
      mode = "bridge"
      port "nginx-http" {
        to = 80
        host_network = "wireguard"
      }
    }

    service {
      name = "depictor-nginx"
      port = "nginx-http"
      tags = [
        "deploy_nonce=DEPLOY_NONCE",
        "traefik.enable=true",
        "traefik.http.routers.depictor.entrypoints=https",
        "traefik.http.routers.depictor.rule=Host(`net-health.en.anyone.tech`)",
        "traefik.http.routers.depictor.tls=true",
        "traefik.http.routers.depictor.tls.certresolver=anyoneresolver",
      ]
      check {
        name     = "nginx http server alive"
        type     = "http"
        path     = "/"
        interval = "10s"
        timeout  = "10s"
        address_mode = "alloc"
        check_restart {
          limit = 10
          grace = "30s"
        }
      }
    }

    task "depictor-nginx-task" {
      driver = "docker"

      config {
        image = "ghcr.io/anyone-protocol/depictor:DEPLOY_TAG"
        force_pull = true
        ports = ["nginx-http"]
      }

      env {
        CRON_SCHEDULE = "5 * * * *"
        DOWNLOAD_STATS_MAX_SIZE_MB = "100"
        DOWNLOAD_STATS_KEEP_LINES = "20000"
      }

      resources {
        cpu    = 2048
        memory = 4096 # python script is memory hungry :(
      }
    }
  }
}
