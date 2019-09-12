Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/bionic64"

  # config.vm.box_check_update = false

  config.vm.synced_folder ".", "/opt/irma2saml"

  config.vm.network "forwarded_port", guest: 443, host: 8443

  config.vm.provision "ansible" do |ansible|
    ansible.playbook = "ansible/playbook.yml"
  end
end
