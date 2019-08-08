ruleset io.picolabs.safeandmine {
  meta {
    shares __testing, getInformation, getTags
    use module io.picolabs.wrangler alias Wrangler
    use module io.picolabs.subscription alias sub
  }
  global {
    __testing = { "queries":
      [ { "name": "__testing" }
        , { "name": "getInformation", "args" : [ "info" ] }
        , { "name": "getTags" }
      ] , "events":
      [ { "domain": "safeandmine", "type": "update", "attrs" : [ "name" ] }
      , { "domain": "safeandmine", "type": "delete", "attrs": [ "toDelete" ] }
      , { "domain": "safeandmine", "type": "new_tag", "attrs": [ "tagID", "domain" ] }
      , { "domain": "safeandmine", "type": "deregister", "attrs": [ "tagID", "domain" ] }
      , { "domain": "safeandmine", "type": "notify", "attrs": [ "tagID" ] }
      , { "domain": "apps", "type": "cleanup" }
      , { "domain": "safeandmine", "type": "update_registry_eci", "attrs": [ "eci" ] }
      ]
    }
    
    
    getInformation = function(info) {
      data = ent:contactInfo.defaultsTo({});
      info => data{info} | data
    }
    
    getTags = function() {
      ent:tagStore.defaultsTo({}).map(function(v,k) {
        v.keys()
      });
    }
    
    app = {"name":"safeandmine","version":"0.0"/* img: , pre: , ..*/};
    bindings = function(){
      {
        //currently no bindings
      };
    }
    
    getPolicyID = function(){
      engine:listPolicies().filter(function(x){x{"name"} == "registry pico events only"})[0]{"id"}
    }
    
    policy = {
      "name" : "registry pico events only",
      "query" : {
          "allow" : [
            { "rid" : "io.picolabs.safeandmine", "name" : "getInformation"}
            ]
      },
      "event" : {
        "allow" : [
          { "domain" : "safeandmine", "type" : "notify" }
          , { "domain" : "safeandmine", "type" : "tag_register_response" }
          ]
      }
    }
    
    META_FIELD_LENGTH = 100
    MESSAGE_CHAR_LENGTH = 250
  }
  
  rule update_registry_eci {
    select when safeandmine update_registry_eci
    
    pre {
      eci = event:attr("eci")
    }
    
    if eci then noop();
    
    fired {
      ent:registry_eci := eci;
    }
  }
  
  rule discovery { select when manifold apps send_directive("app discovered...", {"app": app, "rid": meta:rid, "bindings": bindings(), "iconURL": "https://image.flaticon.com/icons/svg/172/172076.svg"} ); }

  rule update_tag_store {
    select when manifold apps
    
    pre {
      domains = ent:tagStore.defaultsTo({}).values().klog("Values");
      needsUpdate = (domains.klog("domain").head().typeof() == "Map").klog("hasDomain") && ent:tagStore != {}
    }
    
    if needsUpdate then noop();
    
    notfired {
      ent:tagStore := {}.put("sqtg", ent:tagStore);
      raise safeandmine event "update"
    } else {
      raise safeandmine event "update"
    }
    
  }
  
  rule update_policy {
    select when safeandmine update
    
    pre {
      exists = getPolicyID()
    }
    if exists.isnull() then 
      engine:newPolicy(policy);
  }
  
  rule create_policy {
    select when wrangler ruleset_added where rid >< meta:rid
    
    pre {
      exists = getPolicyID()
    }
    if exists.isnull() then 
      engine:newPolicy(policy);
  }
  
  rule information_update {
    select when safeandmine update
    pre {
      name = event:attr("name").defaultsTo(ent:contactInfo{["name"]}).defaultsTo("").substr(0, META_FIELD_LENGTH)
      email = event:attr("email").defaultsTo(ent:contactInfo{["email"]}).defaultsTo("").substr(0, META_FIELD_LENGTH)
      phone = event:attr("phone").defaultsTo(ent:contactInfo{["phone"]}).defaultsTo("").substr(0, META_FIELD_LENGTH)
      message = event:attr("message").defaultsTo(ent:contactInfo{["message"]}).defaultsTo("").substr(0, MESSAGE_CHAR_LENGTH)
      attrs = {
        "name" : name,
        "email" : email,
        "phone" : phone,
        "message" : message,
        "shareName" : event:attr("shareName").as("Boolean").defaultsTo(false),
        "sharePhone" : event:attr("sharePhone").as("Boolean").defaultsTo(false),
        "shareEmail" : event:attr("shareEmail").as("Boolean").defaultsTo(false)
      }
    }
    always {
      ent:contactInfo := ent:contactInfo.defaultsTo({}).put(attrs);
    }
    
  }
  
  rule information_delete {
    select when safeandmine delete
    
    pre {
      toDelete = event:attr("toDelete")
    }
    
    if toDelete then noop();
    
    notfired {
      ent:contactInfo := {}
    } else {
      ent:contactInfo := ent:contactInfo.delete([toDelete])
    }
    
  }
  
  rule new_tag {
    select when safeandmine new_tag
    
    pre {
      tagID = event:attr("tagID").as("String");
      domain = event:attr("domain").as("String");
    }
    
      if (tagID.length() > 1) then 
        noop();
    
      fired {
        raise safeandmine event "new_tag_channel"
          attributes {
            "tagID" : tagID.uc(),
            "domain" : domain
          }
      }
  }
  
  rule create_tag_channel {
    select when safeandmine new_tag_channel
    
    always {
      raise wrangler event "channel_creation_requested"
        attributes {
          "name" : event:attr("domain") + "/" + event:attr("tagID"),
          "type" : "tagRegistry",
          "policy_id" : getPolicyID(),
          "attrs" : event:attrs
        }
    }
  }
  
  rule send_registry_request {
    select when wrangler channel_created
    
    pre {
      tagID = event:attr("attrs"){"tagID"}.klog("TAGID");
      domain = event:attr("attrs"){"domain"}.klog("DOMAIN");
      channel = event:attr("channel"){"id"}.klog("CHANNEL");
    }
    
    event:send({"eci": ent:registry_eci.defaultsTo("CEmo7mURALxUzEVLkN2Fwc"), "domain": "safeandmine", "type": "register_tag", "attrs" : { "tagID" : tagID, "DID" : channel, "domain" : domain } });
    //http:post("http://localhost:3001/safeandmine/api/tags", json = { "tagID" : tagID, "DID" : channel, "domain" : domain }, autoraise=channel ) setting(resp)
    //http:post("https://apps.picolabs.io/safeandmine/api/tags", json = { "tagID" : tagID, "DID" : channel }, autoraise=channel ) setting(resp)
    
    always {
      ent:channels := ent:channels.defaultsTo([]).append(channel)
    }
    
  }
  
  rule post_response {
    select when safeandmine tag_register_response
    
    pre{
      tagID = event:attr("tagID");
      DID = event:attr("DID");
      domain = event:attr("domain");
    }
    if ( tagID && DID) then noop();
    
    fired {
      ent:tagStore := ent:tagStore.defaultsTo({}).put([domain, tagID], DID);
    }
    else {
      raise safeandmine event "cleanup" attributes event:attrs
    }
  }
  
  rule channel_cleanup {
    select when safeandmine cleanup where ent:channels >< event:attr("label")
    
    always {
      ent:channels := ent:channels.splice(ent:channels.index(event:attr("label")), 1);
      
      raise wrangler event "channel_deletion_requested"
          attributes {
            "eci" : event:attr("label")
          }
    }
  }
  
  rule deregister_tag {
    select when safeandmine deregister
    
    pre {
      tagToDelete = event:attr("tagID");
      domain = event:attr("domain");
      channelToDelete = ent:tagStore.get([domain, tagToDelete]);
    }
    
    if tagToDelete && channelToDelete then 
    event:send({"eci": ent:registry_eci.defaultsTo("CEmo7mURALxUzEVLkN2Fwc"), "domain": "safeandmine", "type": "deregister_tag", "attrs" : { "tagID" : tagToDelete, "domain" : domain } });
    //http:post("https://apps.picolabs.io/safeandmine/api/delete", json = { "tagID" : tagToDelete });
    //http:post("http://localhost:3001/safeandmine/api/delete", json = { "tagID" : tagToDelete, "domain" : domain });
    
    fired{
      ent:tagStore := ent:tagStore.defaultsTo({}).delete([domain,tagToDelete]).filter(function(v,k) {
        v.length() > 0
      });
      raise safeandmine event "cleanup"
      attributes {
        "label" : channelToDelete
      }
    }
  }
  
  rule deregister_all {
    select when apps cleanup
    
    foreach ent:tagStore setting (tags, domain)
      foreach tags.klog("tags") setting (did, tagID)
    
    always {
      raise safeandmine event "deregister"
      attributes {
        "domain" : domain.klog("domain"),
        "tagID" : tagID.klog("tagID")
      }
    }
    
  }
  
  rule notify {
    select when safeandmine notify
    
    pre {
      toSend = sub:established().filter(function(x) {
        x{"Tx_role"} == "manifold_pico"
      }).head(){"Tx"};
      tagID = event:attr("tagID");
      picoId = meta:picoId;
      app = "SafeAndMine";
      rid = meta:rid;
      name = Wrangler:name();
      message = "Your tag " + tagID + " has been scanned";
      attrs = { 
        "picoId" : picoId,
        "thing" : name,
        "app" : app,
        "message" : message,
        "ruleset" : rid
      }
    }
    
    if tagID && picoId && app && rid && name && message && toSend then 
      event:send({ "eci" : toSend, "domain" : "manifold", "type" : "add_notification", "attrs" : attrs})
    
    
  }
  
}
