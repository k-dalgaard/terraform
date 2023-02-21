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


  apps = jsondecode(file("apps.json"))

  epgs = flatten([
    for app_name, epgs in local.apps: [
        for epg in epgs: {
          app_name = app_name
          epg_name = epg.name
          bd = epg.bd
          vlan = epg.vlan
          prov = epg.prov
          cons = epg.cons
          domains = epg.domains
      }]
  ])

  contract_relationships = flatten([
    [for epg in local.epgs: [
      for filter in epg.prov: {
        epg_name = epg.epg_name
        app_name = epg.app_name
        type = "provider"
        contract = length(regexall(".*/brc-.*", filter)) > 0 ? filter : "${epg.app_name}-${epg.epg_name}-${filter}"
      }
    ]],
    [for epg in local.epgs: [
      for filter in epg.cons: {
        epg_name = epg.epg_name
        app_name = epg.app_name
        type = "consumer"
        contract = length(regexall(".*/brc-.*", filter)) > 0 ? filter : "${epg.app_name}-${epg.epg_name}-${filter}"
      }
    ]]
  ])

  accessports = jsondecode(file("accessports.json"))


}


resource "aci_physical_domain" "bare_metal" {
  name  = "BARE-METAL"
  relation_infra_rs_vlan_ns = "uni/infra/vlanns-[BARE-METAL]-static"
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

########################
## applicartion profiles
########################


resource "aci_application_profile" "KDA" {
  for_each = toset([for app_name, epg in local.apps: app_name])
  tenant_dn = aci_tenant.KDA.id
  name = each.value
}


resource "aci_application_epg" "KDA" {
  for_each = {for epg in local.epgs: "${epg.app_name}-${epg.epg_name}" => epg}
  application_profile_dn = aci_application_profile.KDA[each.value.app_name].id
  relation_fv_rs_bd = aci_bridge_domain.KDA[each.value.bd].id
  name = each.value.epg_name
}


resource "aci_epg_to_contract" "brc" {
  for_each           = { for rel in local.contract_relationships : "${rel.app_name}-${rel.epg_name}-${rel.type}-${rel.contract}" => rel if length(regexall(".*/brc-.*", rel.contract)) > 0}
  application_epg_dn = aci_application_epg.KDA["${each.value.app_name}-${each.value.epg_name}"].id
  contract_dn        = each.value.contract
  contract_type      = each.value.type
}

resource "aci_epg_to_domain" "bare_metal" {
  for_each = {for epg in local.epgs: "${epg.app_name}-${epg.epg_name}" => epg if contains(epg.domains, "BARE-METAL")}
  application_epg_dn    = aci_application_epg.KDA[each.key].id
  tdn                   = aci_physical_domain.bare_metal.id
}

############################
### access-ports          ##
###########################


resource "aci_epg_to_static_path" "accessports" {
  for_each = {
    for accessport in local.accessports: "${accessport.leaf}-${accessport.port}" => accessport
  }
  application_epg_dn  = aci_application_epg.KDA[each.value.epg].id
  tdn  = "topology/pod-${each.value.pod}/paths-${each.value.leaf}/pathep-[eth1/${each.value.port}]"
  encap  = "vlan-${each.value.vlan}"
  instr_imedcy = "immediate"
  mode  = "native"
}


resource "aci_vlan_pool" "bare-metal" {
  name  = "BARE-METAL"
  alloc_mode  = "static"
}


resource "aci_ranges" "range" {
  for_each = {for epg in local.epgs: "${epg.app_name}-${epg.epg_name}" => epg}
  vlan_pool_dn  = aci_vlan_pool.bare-metal.id
  from          = "vlan-${each.value.vlan}"
  to            = "vlan-${each.value.vlan}"
  alloc_mode    = "inherit"
}

resource "aci_attachable_access_entity_profile" "access_ports" {
  name        = "ACCESS-PORTS"
}

resource "aci_aaep_to_domain" "access_ports_bare_metal" {
  attachable_access_entity_profile_dn = aci_attachable_access_entity_profile.access_ports.id
  domain_dn                           = aci_physical_domain.bare_metal.id
}

resource "aci_leaf_access_port_policy_group" "fooleaf_access_port_policy_group" {
    name        = "ACCESS-PORTS"
    relation_infra_rs_att_ent_p = "uni/infra/attentp-ACCESS-PORTS"
}




#######################################
####   hvad gør denne ???


resource "aci_attachable_access_entity_profile" "l2_migration" {
  name        = "L2-MIGRATION"
}

resource "aci_aaep_to_domain" "l2_migration_bare_metal" {
  attachable_access_entity_profile_dn = aci_attachable_access_entity_profile.l2_migration.id
  domain_dn                           = aci_physical_domain.bare_metal.id
}

resource "aci_access_generic" "l2_migration" {
  attachable_access_entity_profile_dn   = aci_attachable_access_entity_profile.l2_migration.id
  name                                  = "default"
}

resource "aci_epgs_using_function" "l2_migration" {
  for_each = {for epg in local.epgs: "${epg.app_name}-${epg.epg_name}" => epg}
  access_generic_dn   = aci_access_generic.l2_migration.id
  tdn                 = aci_application_epg.KDA[each.key].id
  encap               = "vlan-${each.value.vlan}"
  instr_imedcy        = "immediate"
}