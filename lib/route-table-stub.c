/* Copyright (c) 2012, 2013, 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#include <config.h>

#include "compiler.h"
#include "ovs-router.h"
#include "route-table.h"

bool
ovs_router_lookup(ovs_be32 ip_dst OVS_UNUSED, char output_bridge[] OVS_UNUSED,
                  ovs_be32 *gw)
{
    *gw = 0;
    return false;
}

void
ovs_router_unixctl_register(void)
{
}

uint64_t
route_table_get_change_seq(void)
{
    return 0;
}

void
route_table_register(void)
{
}

void
route_table_unregister(void)
{
}

void
route_table_run(void)
{
}

void
route_table_wait(void)
{
}
