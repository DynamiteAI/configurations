// This file was automatically generated by bifcl from /tmp/dynamite/install_cache/configurations/base/default_configs/zeek/uncompiled_scripts/zeek-community-id-3.2.1/src/communityid.bif (plugin mode).


#include <list>
#include <string>
#include "zeek/plugin/Plugin.h"
#include "zeek/Func.h"
#include "communityid.bif.h"

namespace plugin { namespace Corelight_CommunityID {

void __bif_communityid_init(zeek::plugin::Plugin* plugin)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

	(void) new zeek::detail::BuiltinFunc(zeek::BifFunc::CommunityID::hash_conn_bif, "CommunityID::hash_conn", 0);
	plugin->AddBifItem("CommunityID::hash_conn", zeek::plugin::BifItem::FUNCTION);


#pragma GCC diagnostic pop

	}
} }


