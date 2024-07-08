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
      force_pull = true

      config {
        image = "svforte/depictor:latest"
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
          "traefik.enable=true",
          "traefik.http.routers.deb-repo.entrypoints=https",
          "traefik.http.routers.deb-repo.rule=Host(`netowork-health.dmz.ator.dev`)",
          "traefik.http.routers.deb-repo.tls=true",
          "traefik.http.routers.deb-repo.tls.certresolver=atorresolver",
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
