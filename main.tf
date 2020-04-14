provider "google" {
  project = var.project
  region  = var.region
  zone    = var.zone
}

provider "google-beta" {
  project = var.project
  region  = var.region
  zone    = var.zone
}

data "google_compute_network" "mirror-network" {
  name = "default"
}

data "google_compute_subnetwork" "mirror-subnet" {
  name = "default-${var.zone}"
  region = var.region
}

resource "google_compute_instance_template" "web-server-template" {
  name        = "web-server-template"
  description = "This template is used to create web server instances."
  
  instance_description = "description assigned to instances"
  machine_type         = "f1-micro"

  network_interface {
    network = data.google_compute_network.mirror-network.self_link
  }

  disk {
    source_image = "ubuntu-1804-lts"
  }

  tags = ["http", "ssh"]

  metadata_startup_script = file("web-startup.sh")
}

resource "google_compute_instance_template" "ids-template" {
  name        = "ids-template"
  description = "This template is used to create IDS instances."
  
  instance_description = "description assigned to instances"
  machine_type         = "n1-standard-2"

  service_account {
    scopes = ["compute-rw"]
  }

  network_interface {
    network = data.google_compute_network.mirror-network.self_link
  }

  disk {
    source_image = "ubuntu-1804-lts"
  }

  tags = ["ssh"]

  metadata_startup_script = file("ids-startup.sh")
}

resource "google_compute_health_check" "ssh-health-check" {
  name                = "ssh-health-check"
  check_interval_sec  = 5
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 10 # 50 seconds

  tcp_health_check {
    port         = "22"
  }
}

resource "google_compute_instance_group_manager" "webserver" {
  name = "webserver-ig"

  base_instance_name = "web"
  zone               = "us-central1-c"

  version {
    instance_template  = google_compute_instance_template.web-server-template.self_link
  }

  target_size  = 2

  auto_healing_policies {
    health_check      = google_compute_health_check.ssh-health-check.self_link
    initial_delay_sec = 300
  }
}

resource "google_compute_instance_group_manager" "ids" {
  name = "ids-ig"

  base_instance_name = "ids"
  zone               = "us-central1-c"

  version {
    instance_template  = google_compute_instance_template.ids-template.self_link
  }

  target_size  = 1

  auto_healing_policies {
    health_check      = google_compute_health_check.ssh-health-check.self_link
    initial_delay_sec = 300
  }
}

resource "google_compute_router" "router" {
  name    = "nat-router"
  network = "default"
}

resource "google_compute_router_nat" "nat_manual" {
  name   = "nat-router"
  nat_ip_allocate_option = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  router = google_compute_router.router.name
}

resource "google_compute_firewall" "http" {
  name    = "http-in"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  target_tags   = ["http"]
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "ssh" {
  name    = "ssh-in"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  target_tags   = ["ssh"]
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_target_https_proxy" "https-proxy" {
  name             = "https-proxy"
  url_map          = google_compute_url_map.default.self_link
  ssl_certificates = [google_compute_ssl_certificate.ssl-cert.self_link]
  quic_override = "ENABLE"
  depends_on = [google_compute_ssl_certificate.ssl-cert]
}

resource "google_compute_security_policy" "zeek-policy" {
  name = "zeek-policy"

  rule {
    action   = "deny(403)"
    priority = "0"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-stable')"
      }
    }
    description = "OWASP SQLi"
  }
  
  rule {
    action   = "deny(403)"
    priority = "1"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-stable')"
      }
    }
    description = "OWASP XSS"
  }

  rule {
    action   = "allow"
    priority = "1000"
    match {
      expr {
        expression = "request.path == \"/\""
      }
    }
    description = "Whitelist homepage (1 of 2)"
  }

  rule {
    action   = "allow"
    priority = "1001"
    match {
      expr {
        expression = "request.path == \"/index.html\""
      }
    }
    description = "Whitelist homepage (2 of 2)"
  }

  rule {
    action   = "allow"
    priority = "1002"
    match {
      expr {
        expression = "request.path == \"/admin.php\""
      }
    }
    description = "Whitelist admin page"
  }

  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default rule"
  }
}

resource "google_compute_ssl_certificate" "ssl-cert" {
  name_prefix = "web-certificate-"
  private_key = file(var.key)
  certificate = file(var.cert)

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_url_map" "default" {
  name        = "url-map"
  description = var.url
  default_service = google_compute_backend_service.http-backend.self_link
  host_rule {
    hosts        = [var.url]
    path_matcher = "allpaths"
  }
  path_matcher {
    name            = "allpaths"
    default_service = google_compute_backend_service.http-backend.self_link
    path_rule {
      paths   = ["/*"]
      service = google_compute_backend_service.http-backend.self_link
    }
  }
}

resource "google_compute_backend_service" "http-backend" {
  name        = "backend-service"
  port_name   = "http"
  protocol    = "HTTP"
  timeout_sec = 10
  backend {
    group = google_compute_instance_group_manager.webserver.instance_group
  }
  health_checks = [google_compute_health_check.ssh-health-check.self_link]
  security_policy = google_compute_security_policy.zeek-policy.self_link
}

resource "google_compute_global_forwarding_rule" "default" {
  name       = "global-rule"
  target     = google_compute_target_https_proxy.https-proxy.self_link
  port_range = "443"
}

output "external_web_ip" {
  description = "Add this IP to your DNS as an A record for your domain"
  value = google_compute_global_forwarding_rule.default.ip_address
}

resource "google_compute_region_backend_service" "ids-backend" {
  name                  = "ids-backend"
  region                = var.region
  backend {
    group = google_compute_instance_group_manager.ids.instance_group
  }
  health_checks         = [google_compute_health_check.ssh-health-check.self_link]
}

resource "google_compute_forwarding_rule" "packet-mirror-rule" {
  provider = google-beta
  name       = "packet-mirror-ilb"
  is_mirroring_collector = true
  ip_protocol            = "TCP"
  load_balancing_scheme  = "INTERNAL"
  backend_service        = google_compute_region_backend_service.ids-backend.self_link
  all_ports              = true
  network                = data.google_compute_network.mirror-network.self_link
  subnetwork             = data.google_compute_subnetwork.mirror-subnet.self_link
  network_tier           = "PREMIUM"
}

resource "google_compute_packet_mirroring" "ids-mirror" {
  name = "ids-mirror"
  provider = google-beta
  description = "Packet Mirror for IDS instances"
  network  {
    url = data.google_compute_network.mirror-network.self_link
  }
  collector_ilb {
    url = google_compute_forwarding_rule.packet-mirror-rule.self_link
  }
  mirrored_resources {
    tags = ["http"]
  }
}