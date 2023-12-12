/*
 * \brief  ROM session implementation for serving dynamic content
 * \author Norman Feske
 * \date   2016-11-03
 */

/*
 * Copyright (C) 2016-2017 Genode Labs GmbH
 *
 * This file is part of the Genode OS framework, which is distributed
 * under the terms of the GNU Affero General Public License version 3.
 */

#ifndef _INCLUDE__OS__DYNAMIC_ROM_SESSION_H_
#define _INCLUDE__OS__DYNAMIC_ROM_SESSION_H_

#include <util/reconstructible.h>
#include <util/xml_generator.h>
#include <base/rpc_server.h>
#include <base/session_label.h>
#include <base/attached_ram_dataspace.h>
#include <rom_session/rom_session.h>

namespace Genode { class Dynamic_rom_session; }


class Genode::Dynamic_rom_session : public Rpc_object<Rom_session>
{
	public:

		struct Content_producer : Interface
		{
			using Buffer_capacity_exceeded = Xml_generator::Buffer_exceeded;

			/**
			 * Write content into the specified buffer
			 *
			 * \throw  Buffer_capacity_exceeded
			 */
			virtual void produce_content(char *dst, size_t dst_len) = 0;
		};

		class Xml_producer : public Content_producer
		{
			public:

				typedef String<64> Node_name;

			private:

				Node_name const _node_name;

				void produce_content(char *dst, size_t dst_len) override
				{
					Xml_generator xml(dst, dst_len, _node_name.string(), [&] () {
						produce_xml(xml); });
				}

			public:

				Xml_producer(Node_name node_name) : _node_name(node_name) { }

				/**
				 * Generate ROM content
				 *
				 * \throw Xml_generator::Buffer_exceeded
				 */
				virtual void produce_xml(Xml_generator &) = 0;
		};

	private:

		/*
		 * Synchronize calls of 'trigger_update' (called locally) with the
		 * 'Rom_session' methods (invoked via RPC).
		 */
		Mutex _mutex { };

		Rpc_entrypoint            &_ep;
		Ram_allocator             &_ram;
		Region_map                &_rm;
		Signal_context_capability  _sigh { };
		Content_producer          &_content_producer;

		/*
		 * Keep track of the last version handed out to the client (at the
		 * time of the last 'Rom_session::update' RPC call, and the newest
		 * version that is available. If the client version is out of date
		 * when the client registers a signal handler, submit a signal
		 * immediately.
		 */
		unsigned _current_version = 0, _client_version = 0;

		size_t _ds_size = 4096;

		Constructible<Attached_ram_dataspace> _ds { };

		void _notify_client()
		{
			if (_sigh.valid() && (_current_version != _client_version))
				Signal_transmitter(_sigh).submit();
		}

		bool _unsynchronized_update()
		{
			bool ds_reallocated = false;

			for (;;) {
				try {
					if (!_ds.constructed()) {
						_ds.construct(_ram, _rm, _ds_size);
						ds_reallocated = true;
					}
				}
				catch (Out_of_ram) {

					error("ouf of child RAM quota while delivering dynamic ROM");

					/*
					 * XXX We may try to generate a resource request on
					 *     behalf of the child.
					 */

					/*
					 * Don't let the child try again to obtain a dataspace
					 * by pretending that the ROM module is up-to-date.
					 */
					return true;
				}
				catch (Out_of_caps) {

					error("ouf of child cap quota while delivering dynamic ROM");

					/*
					 * XXX We may try to generate a resource request on
					 *     behalf of the child.
					 */

					/*
					 * Don't let the child try again to obtain a dataspace
					 * by pretending that the ROM module is up-to-date.
					 */
					return true;
				}

				try {
					_content_producer.produce_content(_ds->local_addr<char>(),
					                                  _ds->size());
					_client_version = _current_version;
					return !ds_reallocated;
				}
				catch (Content_producer::Buffer_capacity_exceeded) {

					/* force the re-allocation of a larger buffer */
					_ds.destruct();
					_ds_size *= 2;
				}
			}
		}

	public:

		Dynamic_rom_session(Rpc_entrypoint   &ep,
		                    Ram_allocator    &ram,
		                    Region_map       &rm,
		                    Content_producer &content_producer)
		:
			_ep(ep), _ram(ram), _rm(rm), _content_producer(content_producer)
		{
			_ep.manage(this);
		}

		/**
		 * Constructor
		 *
		 * \param ep                entrypoint serving the ROM session
		 * \param ram               Allocator used to allocate the backing
		 *                          store for the dataspace handed out to the
		 *                          client
		 * \param rm                local region map ('env.rm()') required to
		 *                          make the dataspace locally visible to
		 *                          populate its content
		 * \param content_producer  callback to generate the content of the
		 *                          ROM dataspace
		 *
		 * The 'Dynamic_rom_session' associates/disassociates itself with 'ep'.
		 */
		Dynamic_rom_session(Entrypoint       &ep,
		                    Ram_allocator    &ram,
		                    Region_map       &rm,
		                    Content_producer &content_producer)
		:
			Dynamic_rom_session(ep.rpc_ep(), ram, rm, content_producer)
		{ }

		~Dynamic_rom_session() { _ep.dissolve(this); }

		/*
		 * Called locally, potentially from another thread than 'ep'
		 */
		void trigger_update()
		{
			Mutex::Guard guard(_mutex);

			_current_version++;
			_notify_client();
		}


		/***************************
		 ** ROM session interface **
		 ***************************/

		Rom_dataspace_capability dataspace() override
		{
			Mutex::Guard guard(_mutex);

			if (!_ds.constructed())
				_unsynchronized_update();

			if (!_ds.constructed())
				return Rom_dataspace_capability();

			Dataspace_capability ds_cap = _ds->cap();

			return static_cap_cast<Rom_dataspace>(ds_cap);
		}

		bool update() override
		{
			Mutex::Guard guard(_mutex);

			return _unsynchronized_update();
		}

		void sigh(Signal_context_capability sigh) override
		{
			Mutex::Guard guard(_mutex);

			_sigh = sigh;
			_notify_client();
		}
};

#endif /* _INCLUDE__OS__DYNAMIC_ROM_SESSION_H_ */

