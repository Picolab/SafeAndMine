ruleset io.picolabs.safeandmine {
  meta {
    shares __testing, getInformation, getTags
  }
  global {
    __testing = { "queries":
      [ { "name": "__testing" }
        , { "name": "getInformation", "args" : [ "info" ] }
      ] , "events":
      [ { "domain": "safeandmine", "type": "update", "attrs" : [ "name" ] }
      , { "domain": "safeandmine", "type": "delete", "attrs": [ "toDelete" ] }
      , { "domain": "safeandmine", "type": "new_tag", "attrs": [ "tagID" ] }
      ]
    }
    
    getInformation = function(info) {
      data = ent:contactInfo.defaultsTo({});
      info => data{info} | data
    }
    
    getTags = function() {
      ent:tagStore.defaultsTo({}).keys()
    }
    
    app = {"name":"safeandmine","version":"0.0"/* img: , pre: , ..*/};
    bindings = function(){
      {
        //currently no bindings
      };
    }
    
    getPolicyID = function(){
      engine:listPolicies().filter(function(x){x{"name"} == "information requests only"})[0]{"id"}
    }
    
    policy = {
      "name" : "information requests only",
      "query" : {
          "allow" : [
            { "rid" : "io.picolabs.safeandmine", "name" : "getInformation"}
            ]
      }
    }
    
  }
  
  rule discovery { select when manifold apps send_directive("app discovered...", {"app": app, "rid": meta:rid, "bindings": bindings(), "iconURL": "http://images.clipartpanda.com/lock-clipart-clip-art-unlock-clipart-1.jpg"} ); }
  
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
      attrs = event:attrs.filter(function(v,k){k != "_headers"});
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
    }
    
      if (tagID.length() == 6) then noop();
    
      fired {
        raise safeandmine event "new_tag_channel"
          attributes event:attrs
      }
  }
  
  rule create_tag_channel {
    select when safeandmine new_tag_channel
    
    always {
      raise wrangler event "channel_creation_requested"
        attributes {
          "name" : event:attr("tagID"),
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
      channel = event:attr("channel"){"id"}.klog("CHANNEL");
    }
    
    http:post("http://localhost:3001/safeandmine/api/tags", json = { "tagID" : tagID, "DID" : channel }, autoraise=channel ) setting(resp)
    
    always {
      ent:channels := ent:channels.defaultsTo([]).append(channel)
    }
    
  }
  
  rule post_response {
    select when http post
    
    pre{
      content = event:attr("content").decode();
      tagID = content{"tagID"};
      DID = content{"DID"}
    }
    if (event:attr("status_code") == 200 && tagID && DID) then noop();
    
    fired {
      ent:tagStore := ent:tagStore.defaultsTo({}).put(tagID, DID);
    }
    else {
      raise safeandmine event "cleanup" attributes event:attrs
    }
  }
  
  rule channel_cleanup {
    select when safeandmine cleanup where ent:channels >< event:attr("label")
    
    always {
      raise wrangler event "channel_deletion_requested"
          attributes {
            "eci" : event:attr("label")
          }
    }
  }
  
  rule deregister_tag {
    select when safeandmine deregister
    
    pre {
      tagToDelete = event("tagID");
      channelToDelete = ent:tagStore{tagToDelete};
    }
    
    if tagTooDelete && channelToDelete then noop();
    
    fired{
      ent:tagStore := ent:tagStore.delete(tagToDelete);
      raise safeandmine event "cleanup"
      attributes {
        "label" : channelToDelete
      }
    }
  }
  
}
