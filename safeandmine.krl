ruleset io.picolabs.safeandmine {
  meta {
    shares __testing, getInformation
  }
  global {
    __testing = { "queries":
      [ { "name": "__testing" }
        , { "name": "getInformation", "args" : [ "info" ] }
      //, { "name": "entry", "args": [ "key" ] }
      ] , "events":
      [ { "domain": "safeandmine", "type": "update", "attrs" : [ "name" ] }
      , { "domain": "safeandmine", "type": "delete", "attrs": [ "toDelete" ] }
      ]
    }
    
    getInformation = function(info) {
      data = ent:contactInfo.defaultsTo({});
      info => data{info} | data
    }
    
    app = {"name":"safeandmine","version":"0.0"/* img: , pre: , ..*/};
    bindings = function(){
      {
        //currently no bindings
      };
    }
  }
  
  rule discovery { select when manifold apps send_directive("app discovered...", {"app": app, "rid": meta:rid, "bindings": bindings(), "iconURL": "http://images.clipartpanda.com/lock-clipart-clip-art-unlock-clipart-1.jpg"} ); }
  
  rule information_update {
    select when safeandmine update
    
    pre {
      attrs = event:attrs.filter(function(v,k){k != "_headers" && k != "headers"});
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
  
}
