packer {
  required_version = "= 1.16.0"
  required_plugins {
    hyperv = {
      source  = "github.com/hashicorp/hyperv"
      version = "= 1.1.5"
    }
  }
}

variable "iso_path" { type = string }
variable "iso_checksum" { type = string }
variable "switch_name" { type = string }
variable "ssh_private_key_file" { type = string }
variable "bootstrap_password" {
  type      = string
  sensitive = true
}
variable "http_directory" { type = string }
variable "output_directory" { type = string }
variable "vm_name" {
  type    = string
  default = "GREYWARD-DEV-BUILD"
}
variable "ssh_host" {
  type    = string
  default = "greyward-build"
}

source "hyperv-iso" "greyward" {
  vm_name                  = var.vm_name
  generation               = 2
  cpus                     = 4
  memory                   = 8192
  enable_dynamic_memory    = false
  disk_size                = 81920
  disk_block_size          = 1
  switch_name              = var.switch_name
  enable_secure_boot       = true
  secure_boot_template     = "MicrosoftUEFICertificateAuthority"
  first_boot_device        = "DVD"
  iso_url                  = var.iso_path
  iso_checksum             = "sha256:${var.iso_checksum}"
  output_directory         = var.output_directory
  http_directory           = var.http_directory
  communicator             = "ssh"
  ssh_host                 = var.ssh_host
  ssh_username             = "stendev"
  ssh_password             = var.bootstrap_password
  ssh_private_key_file     = var.ssh_private_key_file
  ssh_timeout              = "90m"
  shutdown_command         = "sudo systemctl poweroff"
  headless                 = false

  boot_wait = "10s"
  boot_command = [
    "<up><wait2s>e<wait2s>",
    "<down><down><end>",
    " inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/greyward.ks ip=dhcp inst.text inst.cmdline<wait2s>",
    "<leftCtrlOn>x<leftCtrlOff>"
  ]
}

build {
  sources = ["source.hyperv-iso.greyward"]

  provisioner "shell" {
    inline = ["test -f /etc/greyward-development-bootstrap"]
  }

  # Stage the same production inputs used by a future installed image. The
  # developer overlay and the Security Center component build are separate
  # factory steps below.
  provisioner "file" {
    source      = "${path.root}/production"
    destination = "/tmp/greyward-production"
  }

  provisioner "shell" {
    inline = ["mkdir -p /tmp/greyward-production/session"]
  }

  provisioner "file" {
    source      = "${path.root}/patches/dms/launcher-canonical-hitbox.patch"
    destination = "/tmp/greyward-production/patches/dms/launcher-canonical-hitbox.patch"
  }

  provisioner "file" {
    source      = "${path.root}/patches/dms/polkit-auth-dialog.patch"
    destination = "/tmp/greyward-production/patches/dms/polkit-auth-dialog.patch"
  }

  provisioner "file" {
    source      = "${path.root}/patches/dms/running-apps-icon-scale.patch"
    destination = "/tmp/greyward-production/patches/dms/running-apps-icon-scale.patch"
  }

  provisioner "file" {
    source      = "${path.root}/session/labwc"
    destination = "/tmp/greyward-production/labwc"
  }

  provisioner "file" {
    source      = "${path.root}/session/dankmaterialshell"
    destination = "/tmp/greyward-production/dankmaterialshell"
  }
  # Stage the session files at the production stage root. Do not copy the
  # source directory itself: production/provision.sh consumes this narrow
  # stage layout rather than a nested environment/session tree.
  provisioner "file" {
    source      = "${path.root}/session/greyward-decoration.tokens.conf"
    destination = "/tmp/greyward-production/session/greyward-decoration.tokens.conf"
  }

  provisioner "file" {
    source      = "${path.root}/session/greyward-dms-session-migrate"
    destination = "/tmp/greyward-production/session/greyward-dms-session-migrate"
  }

  provisioner "file" {
    source      = "${path.root}/session/greyward-dms.service"
    destination = "/tmp/greyward-production/session/greyward-dms.service"
  }

  provisioner "file" {
    source      = "${path.root}/session/greyward-labwc.desktop"
    destination = "/tmp/greyward-production/session/greyward-labwc.desktop"
  }

  provisioner "file" {
    source      = "${path.root}/session/greyward-minimize.sh"
    destination = "/tmp/greyward-production/session/greyward-minimize.sh"
  }

  provisioner "file" {
    source      = "${path.root}/session/greyward-restore.sh"
    destination = "/tmp/greyward-production/session/greyward-restore.sh"
  }

  provisioner "file" {
    source      = "${path.root}/session/hyprland.conf"
    destination = "/tmp/greyward-production/session/hyprland.conf"
  }

  provisioner "file" {
    source      = "${path.root}/flatpak"
    destination = "/tmp/greyward-production/flatpak"
  }

  provisioner "file" {
    source      = "${path.root}/../branding"
    destination = "/tmp/greyward-production/branding"
  }

  provisioner "file" {
    source      = "${path.root}/../security-center"
    destination = "/tmp/greyward-security-center"
  }

  provisioner "file" {
    source      = "${path.root}/development/packages.txt"
    destination = "/tmp/greyward-development-packages.txt"
  }

  provisioner "file" {
    source      = "${path.root}/development"
    destination = "/tmp/greyward-development"
  }

  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; sudo -E bash {{ .Path }}"
    inline = [
      "grep -Ev '^[[:space:]]*(#|$)' /tmp/greyward-development-packages.txt | xargs -r dnf -y install",
      "dnf -y builddep /tmp/greyward-security-center/packaging/greyward-security-center.spec",
      "GREYWARD_SECURITY_CENTER_SOURCE=/tmp/greyward-security-center GREYWARD_SECURITY_CENTER_OUTPUT=/tmp/greyward-production/rpms bash /tmp/greyward-development/build-security-center.sh"
    ]
  }

  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; sudo -E bash {{ .Path }}"
    script          = "${path.root}/production/provision.sh"
  }

  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; sudo -E bash {{ .Path }}"
    script          = "${path.root}/development/provision-overlay.sh"
  }

  provisioner "shell" {
    inline = [
      "rpm -q hyprland quickshell uwsm xdg-desktop-portal-hyprland hyperv-daemons greyward-security-center greyward-security-context | tee /tmp/greyward-package-versions.txt",
      "sudo install -m 0644 /tmp/greyward-package-versions.txt /etc/greyward-package-versions.txt",
      "test -f /etc/greyward/production-system",
      "sudo systemctl enable sshd NetworkManager bluetooth",
      "sudo sync"
    ]
  }
}
