ruleset safeandmine {
  meta {
    shares __testing, getInformation
  }
  global {
    __testing = { "queries":
      [ { "name": "__testing" }
        , { "name": "getInformation", "args" : [ "info" ] }
      //, { "name": "entry", "args": [ "key" ] }
      ] , "events":
      [ { "domain": "information", "type": "update", "attrs" : [ "name" ] }
      , { "domain": "information", "type": "delete", "attrs": [ "toDelete" ] }
      ]
    }
    
    getInformation = function(info) {
      info => ent:contactInfo{info} | ent:contactInfo
    }
  }
  
  rule information_update {
    select when information update
    
    pre {
      attrs = event:attrs.filter(function(v,k){k != "_headers"});
    }
    
    always {
      ent:contactInfo := ent:contactInfo.defaultsTo({}).put(attrs);
    }
    
  }
  
  rule information_delete {
    select when information delete
    
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
