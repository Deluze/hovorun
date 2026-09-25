#pragma once

#include "../net/message.hpp"
#include "message_type.hpp"

#include <cstdint>

namespace hovorun::proudnet
{

// Starts an RMI payload: [u8 MessageType::rmi][u16 RmiID]. Parameters follow.
inline net::message_writer rmi_begin(uint16_t rmi_id)
{
    net::message_writer w;
    w.write_u8(static_cast<uint8_t>(message_type::rmi));
    w.write_u16(rmi_id);
    return w;
}

} // namespace hovorun::proudnet
