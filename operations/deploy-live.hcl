job "depictor-live" {
  datacenters = ["ator-fin"]
  type        = "service"
  namespace   = "ator-network"

  group "depictor" {
    count = 1

    constraint {
      attribute = "${node.unique.id}"
      value     = "c8e55509-a756-0aa7-563b-9665aa4915ab"
    }

    network {
      port "nginx-http" {
        static = 8009
        to     = 80
      }
    }

    task "depictor-nginx-task" {
      driver = "docker"

      config {
        image = "ghcr.io/anyone-protocol/depictor:DEPLOY_TAG"
        force_pull = true
        ports = ["nginx-http"]
      }

      resources {
        cpu    = 128
        memory = 128
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
          type     = "tcp"
          interval = "10s"
          timeout  = "10s"
          check_restart {
            limit = 10
            grace = "30s"
          }
        }
      }
    }
  }
}
