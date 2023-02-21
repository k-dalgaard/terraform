terraform {
   required_providers {
      aci = {
        source = "ciscodevnet/aci"
        version = "2.5.2"
      }
  }
}
provider "aci" {
    insecure = true
#    password = var.apic_password
    password = "!v3G@!4@Y"
    url = "https://sandboxapicdc.cisco.com/"
    #username = var.apic_username
    username = "admin"
}

#variable "apic_username" {
#    type = string
#}

#variable "apic_password" {
#    type = string
#    sensitive = true
#}

locals {
  bridgedomains = jsondecode(file("bridgedomains.json"))

  subnets = flatten([
      for bd in local.bridgedomains: [
	        for subnet in bd.subnets: {
		        bd: bd.name
				addr: subnet
				vrf: bd.vrf
		    }
	  ]
  ])
}


resource "aci_physical_domain" "bare_metal" {
  name  = "BARE-METAL"
  #relation_infra_rs_vlan_ns = "uni/infra/vlanns-[BARE-METAL]-static"
}

resource "aci_tenant" "KDA" {
  name = "KDA"
}

resource "aci_vrf" "KDA" {
  for_each = toset([for bd in local.bridgedomains: bd.vrf])
  tenant_dn = aci_tenant.KDA.id
  name = each.value
}



resource "aci_bridge_domain" "KDA" {
  for_each = {for bd in local.bridgedomains: bd.name => bd}
  tenant_dn = aci_tenant.KDA.id
  name = each.value.name
  relation_fv_rs_ctx = aci_vrf.KDA[each.value.vrf].id
  arp_flood = length(each.value.subnets) == 0 || each.value.garp ? "yes" : "no"
  ep_move_detect_mode = each.value.garp ? "garp" : "disable"
  unk_mac_ucast_act = length(each.value.subnets) == 0 ? "flood" : "proxy"
  unicast_route = length(each.value.subnets) == 0 ? "no" : "yes"
 # relation_fv_rs_bd_to_out = length(each.value.subnets) == 0 ? [] : [aci_l3_outside.l3out["${each.value.vrf}-CORE"].id]
  mac = contains(keys(each.value), "mac") ? each.value.mac : "00:22:BD:F8:19:FF"
}

resource "aci_subnet" "KDA" {
  for_each = {for subnet in local.subnets: "${subnet.vrf}-${subnet.addr}" => subnet}
  parent_dn        = aci_bridge_domain.KDA[each.value.bd].id
  ip               = each.value.addr
  scope            = ["public"]
}




