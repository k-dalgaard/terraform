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
    password = var.apic_password
    url = "https://172.31.2.83"
    username = var.apic_username
}

variable "apic_username" {
    type = string
}

variable "apic_password" {
    type = string
    sensitive = true
}

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


  l3outs = jsondecode(file("l3outs.json"))


  domains = toset([
    for l3out in local.l3outs: l3out.domain
  ])

  vrfs = toset([
    for l3out in local.l3outs: l3out.vrf
  ])

  l3out_prov_filters = flatten([
    for l3out in local.l3outs: [
        for prov in l3out.prov: {
            domain: l3out.domain,
            vrf: l3out.vrf,
            filter: prov
        }
    ]
  ])

  l3out_cons_filters = flatten([
    for l3out in local.l3outs: [
        for cons in l3out.cons: {
            domain: l3out.domain,
            vrf: l3out.vrf,
            filter: cons
        }
    ]
  ])

  l3out_paths = flatten([
    for l3out in local.l3outs: [
        for node_id, node in l3out.nodes: [
            for intf in node.interfaces: {
                l3out_name: "${l3out.vrf}-${l3out.domain}",
                pod: node.pod,
                node: node_id,
                intf: intf.intf,
                addr: intf.addr,
                vlan: l3out.vlan,
                mtu: l3out.mtu
            }
        ]
    ]
  ])

  l3out_nodes = flatten([
    for l3out in local.l3outs: [
        for node_id, node in l3out.nodes: {
            l3out_name: "${l3out.vrf}-${l3out.domain}",
            pod: node.pod,
            node: node_id,
            router_id: node.router_id
        }
    ]
  ])

  bgp_peers = flatten([
    for l3out in local.l3outs: [
        for node_id, node in l3out.nodes: [
            for intf in node.interfaces: {
                vrf: l3out.vrf,
                node: node_id,
                intf: intf.intf,
                addr: intf.bgp_peer,
                vlan: l3out.vlan,
                remote_as: l3out.bgp_remote_as
            }
        ]
    ]
    if contains(keys(l3out), "bgp_remote_as")
  ])

}


resource "aci_physical_domain" "bare_metal" {
  name  = "BARE-METAL"
  relation_infra_rs_vlan_ns = "uni/infra/vlanns-[BARE-METAL]-static"
}

resource "aci_tenant" "DAC" {
  name = "DAC"
}

resource "aci_vrf" "DAC" {
  for_each = toset([for bd in local.bridgedomains: bd.vrf])
  tenant_dn = aci_tenant.DAC.id
  name = each.value
}

#resource "aci_bridge_domain" "DAC" {
#  for_each = {for bd in local.bridgedomains: bd.name => bd}
#  tenant_dn = aci_tenant.DAC.id
#  name = each.value.name
#  relation_fv_rs_ctx = aci_vrf.DAC[each.value.vrf].id
#  arp_flood = length(each.value.subnets) > 0 ? "no" : "yes"
#  unk_mac_ucast_act = length(each.value.subnets) > 0 ? "proxy" : "flood"
#  unicast_route = length(each.value.subnets) > 0 ? "yes" : "no"
#}


resource "aci_bridge_domain" "DAC" {
  for_each = {for bd in local.bridgedomains: bd.name => bd}
  tenant_dn = aci_tenant.DAC.id
  name = each.value.name
  relation_fv_rs_ctx = aci_vrf.DAC[each.value.vrf].id
  arp_flood = length(each.value.subnets) == 0 || each.value.garp ? "yes" : "no"
  ep_move_detect_mode = each.value.garp ? "garp" : "disable"
  unk_mac_ucast_act = length(each.value.subnets) == 0 ? "flood" : "proxy"
  unicast_route = length(each.value.subnets) == 0 ? "no" : "yes"
  relation_fv_rs_bd_to_out = length(each.value.subnets) == 0 ? [] : [aci_l3_outside.l3out["${each.value.vrf}-CORE"].id]
  mac = contains(keys(each.value), "mac") ? each.value.mac : "00:22:BD:F8:19:FF"
}

resource "aci_subnet" "DAC" {
  for_each = {for subnet in local.subnets: "${subnet.vrf}-${subnet.addr}" => subnet}
  parent_dn        = aci_bridge_domain.DAC[each.value.bd].id
  ip               = each.value.addr
  scope            = ["public"]
}



resource "aci_application_profile" "DAC" {
  for_each = toset([for app_name, epg in local.apps: app_name])
  tenant_dn = aci_tenant.DAC.id
  name = each.value
}

resource "aci_application_epg" "DAC" {
  for_each = {for epg in local.epgs: "${epg.app_name}-${epg.epg_name}" => epg}
  application_profile_dn = aci_application_profile.DAC[each.value.app_name].id
  relation_fv_rs_bd = aci_bridge_domain.DAC[each.value.bd].id
  name = each.value.epg_name
}

resource "aci_epg_to_contract" "brc" {
  for_each           = { for rel in local.contract_relationships : "${rel.app_name}-${rel.epg_name}-${rel.type}-${rel.contract}" => rel if length(regexall(".*/brc-.*", rel.contract)) > 0}
  application_epg_dn = aci_application_epg.DAC["${each.value.app_name}-${each.value.epg_name}"].id
  contract_dn        = each.value.contract
  contract_type      = each.value.type
}

resource "aci_epg_to_domain" "bare_metal" {
  for_each = {for epg in local.epgs: "${epg.app_name}-${epg.epg_name}" => epg if contains(epg.domains, "BARE-METAL")}
  application_epg_dn    = aci_application_epg.DAC[each.key].id
  tdn                   = aci_physical_domain.bare_metal.id
}

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
  tdn                 = aci_application_epg.DAC[each.key].id
  encap               = "vlan-${each.value.vlan}"
  instr_imedcy        = "immediate"
}

#resource "aci_attachable_access_entity_profile" "ucs" {
#  name        = "UCS"
#}
#
#resource "aci_aaep_to_domain" "ucs_bare_metal" {
#  attachable_access_entity_profile_dn = aci_attachable_access_entity_profile.ucs.id
#  domain_dn                           = aci_physical_domain.bare_metal.id
#}
#
#resource "aci_access_generic" "ucs" {
#  attachable_access_entity_profile_dn   = aci_attachable_access_entity_profile.ucs.id
#  name                                  = "default"
#}
#
#resource "aci_epgs_using_function" "ucs" {
#  for_each = {
#    for epg in local.epgs: "${epg.app_name}-${epg.epg_name}" => epg
#    if contains(epg.domains, "BARE-METAL")
#  }
#  access_generic_dn   = aci_access_generic.ucs.id
#  tdn                 = aci_application_epg.DAC[each.key].id
#  encap               = "vlan-${each.value.vlan}"
#  instr_imedcy        = "immediate"
#}
#
#resource "aci_attachable_access_entity_profile" "esxi" {
#  name        = "ESXI"
#}
#
#resource "aci_aaep_to_domain" "esxi_bare_metal" {
#  attachable_access_entity_profile_dn = aci_attachable_access_entity_profile.esxi.id
#  domain_dn                           = aci_physical_domain.bare_metal.id
#}
#
#resource "aci_access_generic" "esxi" {
#  attachable_access_entity_profile_dn   = aci_attachable_access_entity_profile.esxi.id
#  name                                  = "default"
#}
#
#resource "aci_epgs_using_function" "esxi" {
#  for_each = {
#    for epg in local.epgs: "${epg.app_name}-${epg.epg_name}" => epg
#    if contains(epg.domains, "BARE-METAL")
#  }
#  access_generic_dn   = aci_access_generic.esxi.id
#  tdn                 = aci_application_epg.solar[each.key].id
#  encap               = "vlan-${each.value.vlan}"
#  instr_imedcy        = "immediate"
#}
#




resource "aci_epg_to_static_path" "accessports" {
  for_each = {
    for accessport in local.accessports: "${accessport.leaf}-${accessport.port}" => accessport
  }
  application_epg_dn  = aci_application_epg.DAC[each.value.epg].id
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





#############
### L3OUT ###
#############


#resource "aci_vlan_pool" "l3o-core-pool" {
#  name  = "L3OUT-CORE"
#  alloc_mode  = "static"
#}
#
#resource "aci_ranges" "range_1" {
#  vlan_pool_dn  = aci_vlan_pool.l3o-core-pool.id
#  from          = "vlan-3201"
#  to            = "vlan-3219"
#  alloc_mode    = "inherit"
#}
#
#
#resource "aci_l3_domain_profile" "l3dom-core" {
#  name  = "L3OUT-CORE"
#  relation_infra_rs_vlan_ns = aci_vlan_pool.l3o-core-pool.id
#}
#
#resource "aci_attachable_access_entity_profile" "aaep-core-l3o" {
#  name        = "CORE-L3OUT"
#}
#
#resource "aci_aaep_to_domain" "aaep-core-l3o-domain" {
#  attachable_access_entity_profile_dn = aci_attachable_access_entity_profile.aaep-core-l3o.id
#  domain_dn                           = aci_l3_domain_profile.l3dom-core.id
#}
#
#resource "aci_l3_outside" "l3o-core" {
#    for_each = toset([for bd in local.bridgedomains: bd.vrf])
#    tenant_dn = aci_tenant.DAC.id
#    name = "core_${each.value}"
#    relation_l3ext_rs_l3_dom_att = aci_l3_domain_profile.l3dom-core.id
#    relation_l3ext_rs_ectx = aci_vrf.DAC[each.value].id
#}

#resource "aci_external_network_instance_profile" "fooexternal_network_instance_profile" {
#    for_each = toset([for bd in local.bridgedomains: bd.vrf])
#        l3_outside_dn  = aci_l3_outside.l3o-core[each.value].id
#        name           = "ANY"
#        relation_fv_rs_cons_if = "uni/tn-DAC/brc-vrf01-any-l3out"
#      }


#resource "aci_logical_node_profile" "np-core-vrf01" {
#        l3_outside_dn = "uni/tn-DAC/out-core_vrf01"
#        name          = "BORDER-LEAVES"
#      }
#
#resource "aci_logical_node_to_fabric_node" "example" {
#  logical_node_profile_dn  = aci_logical_node_profile.np-core-vrf01.id
#  tdn               = "topology/pod-1/node-101"
#  rtr_id            = "10.0.1.1"
#  rtr_id_loop_back  = "no"
#}
#
#resource "aci_logical_interface_profile" "bl-int-core-vrf01" {
#    logical_node_profile_dn = aci_logical_node_profile.np-core-vrf01.id
#    name                    = "BORDER-LEAVES-INTERFACES"
#}
#
#resource "aci_l3out_path_attachment" "example" {
#  logical_interface_profile_dn  = aci_logical_interface_profile.bl-int-core-vrf01.id
#  target_dn  = "topology/pod-1/paths-101/pathep-[eth1/52]"
#  if_inst_t = "sub-interface"
#  addr  = "10.20.30.40/16"
#  encap  = "vlan-3201"
#  mtu = "9216"
#}


resource "aci_l3_domain_profile" "l3out" {
  for_each = local.domains
  name  = each.value
  relation_infra_rs_vlan_ns = aci_vlan_pool.l3out[each.value].id
}

resource "aci_vlan_pool" "l3out" {
  for_each = local.domains
  name  = each.value
  alloc_mode  = "static"
}

resource "aci_ranges" "l3out" {
  for_each = {
    for l3out in local.l3outs: "${l3out.domain}-${l3out.vlan}" => l3out
  }
  vlan_pool_dn  = aci_vlan_pool.l3out[each.value.domain].id
  from          = "vlan-${each.value.vlan}"
  to            = "vlan-${each.value.vlan}"
  alloc_mode    = "inherit"
}

resource "aci_attachable_access_entity_profile" "aaep-l3out" {
  for_each = local.domains
  name  = "L3OUT-${each.value}"
  relation_infra_rs_dom_p = [aci_l3_domain_profile.l3out[each.value].id]
}

resource "aci_leaf_access_port_policy_group" "l3out" {
    for_each = local.domains
    name        = "L3OUT-${each.value}"
    relation_infra_rs_att_ent_p = aci_attachable_access_entity_profile.aaep-l3out[each.value].id
}



resource "aci_l3_outside" "l3out" {
    for_each = {
        for l3out in local.l3outs: "${l3out.vrf}-${l3out.domain}" => l3out
    }
    tenant_dn = aci_tenant.DAC.id
    name = "${each.value.vrf}-${each.value.domain}"
    relation_l3ext_rs_l3_dom_att = aci_l3_domain_profile.l3out[each.value.domain].id
    relation_l3ext_rs_ectx = "${aci_tenant.DAC.id}/ctx-${each.value.vrf}"
}


resource "aci_l3out_bgp_external_policy" "l3out" {
    for_each = {
        for l3out in local.l3outs: "${l3out.vrf}-${l3out.domain}" => l3out
        if contains(keys(l3out), "bgp_remote_as")
    }
    l3_outside_dn = aci_l3_outside.l3out[each.key].id
}


resource "aci_logical_node_profile" "l3out" {
    for_each = {
        for l3out in local.l3outs: "${l3out.vrf}-${l3out.domain}" => l3out
    }
    l3_outside_dn = aci_l3_outside.l3out[each.key].id
    name          = "Nodes"
}


resource "aci_logical_node_to_fabric_node" "l3out" {
    for_each = {
        for node in local.l3out_nodes: "${node.l3out_name}-${node.node}" => node
    }
    logical_node_profile_dn  = aci_logical_node_profile.l3out[each.value.l3out_name].id
    tdn               = "topology/pod-${each.value.pod}/node-${each.value.node}"
    rtr_id            = each.value.router_id
    rtr_id_loop_back  = "no"
}

resource "aci_logical_interface_profile" "l3out" {
    for_each = {
        for l3out in local.l3outs: "${l3out.vrf}-${l3out.domain}" => l3out
    }
    logical_node_profile_dn = aci_logical_node_profile.l3out[each.key].id
    name                    = "IPv4"
}


resource "aci_l3out_path_attachment" "l3out" {
    for_each = {
        for path in local.l3out_paths: "${path.node}-${path.intf}-${path.vlan}" => path
    }
    logical_interface_profile_dn  = aci_logical_interface_profile.l3out[each.value.l3out_name].id
    target_dn  = "topology/pod-${each.value.pod}/paths-${each.value.node}/pathep-[eth1/${each.value.intf}]"
    if_inst_t = "sub-interface"
    addr  = each.value.addr
    encap  = "vlan-${each.value.vlan}"
    mtu = each.value.mtu
}

resource "aci_bgp_peer_connectivity_profile" "example" {
    for_each = {
        for bgp_peer in local.bgp_peers: "${bgp_peer.vrf}-${bgp_peer.addr}" => bgp_peer
    }
    parent_dn           = aci_l3out_path_attachment.l3out["${each.value.node}-${each.value.intf}-${each.value.vlan}"].id
    addr                = each.value.addr
    as_number           = each.value.remote_as
}

resource "aci_contract" "l3out-prov" {
    for_each = {
        for l3out in local.l3outs: "${l3out.vrf}-${l3out.domain}" => l3out
    }
    tenant_dn   =  aci_tenant.DAC.id
    name = "L3Out-${each.value.vrf}-${each.value.domain}-ANY-outbound"
}

resource "aci_contract_subject" "l3out-prov" {
    for_each = {
        for l3out in local.l3outs: "${l3out.vrf}-${l3out.domain}" => l3out
    }
    contract_dn   = aci_contract.l3out-prov[each.key].id
    name          = "Permit"
}


resource "aci_contract_subject_filter" "l3out-prov" {
    for_each = {
        for l3out_prov_filter in local.l3out_prov_filters: "${l3out_prov_filter.vrf}-${l3out_prov_filter.domain}-${l3out_prov_filter.filter}" => l3out_prov_filter
    }
    contract_subject_dn  = aci_contract_subject.l3out-prov["${each.value.vrf}-${each.value.domain}"].id
    filter_dn  = each.value.filter
    action = "permit"
}


resource "aci_contract" "l3out-cons" {
    for_each = {
        for l3out in local.l3outs: "${l3out.vrf}-${l3out.domain}" => l3out
    }
    tenant_dn   =  aci_tenant.DAC.id
    name = "L3Out-${each.value.vrf}-${each.value.domain}-ANY-inbound"
}

resource "aci_contract_subject" "l3out-cons" {
    for_each = {
        for l3out in local.l3outs: "${l3out.vrf}-${l3out.domain}" => l3out
    }
    contract_dn   = aci_contract.l3out-cons[each.key].id
    name          = "Permit"
}

resource "aci_contract_subject_filter" "l3out-cons" {
    for_each = {
        for l3out_cons_filter in local.l3out_cons_filters: "${l3out_cons_filter.vrf}-${l3out_cons_filter.domain}-${l3out_cons_filter.filter}" => l3out_cons_filter
    }
    contract_subject_dn  = aci_contract_subject.l3out-cons["${each.value.vrf}-${each.value.domain}"].id
    filter_dn  = each.value.filter
    action = "permit"
}


resource "aci_external_network_instance_profile" "l3out" {
    for_each = {
        for l3out in local.l3outs: "${l3out.vrf}-${l3out.domain}" => l3out
    }
    l3_outside_dn  = aci_l3_outside.l3out[each.key].id
    name           = "ANY"
    relation_fv_rs_prov = [aci_contract.l3out-prov[each.key].id]
    relation_fv_rs_cons = [aci_contract.l3out-cons[each.key].id]
}

resource "aci_l3_ext_subnet" "l3out" {
    for_each = {
        for l3out in local.l3outs: "${l3out.vrf}-${l3out.domain}" => l3out
    }
    external_network_instance_profile_dn  = aci_external_network_instance_profile.l3out[each.key].id
    ip                                    = "0.0.0.0/0"
}

resource "aci_any" "l3out" {
    for_each = local.vrfs
    vrf_dn       = "${aci_tenant.DAC.id}/ctx-${each.value}"
    relation_vz_rs_any_to_cons = flatten([
        for l3out in local.l3outs:
            aci_contract.l3out-prov["${l3out.vrf}-${l3out.domain}"].id
        if l3out.vrf == each.value
    ])
    relation_vz_rs_any_to_prov = flatten([
        for l3out in local.l3outs:
            aci_contract.l3out-cons["${l3out.vrf}-${l3out.domain}"].id
        if l3out.vrf == each.value
    ])
}
