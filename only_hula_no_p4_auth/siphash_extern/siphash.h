#ifndef SIPHASH_
#define SIPHASH_

#include <bm/bm_sim/extern.h>

namespace bm{
	class siphash : public bm::ExternType {
		public:
			void init() override;
			void digest(const Data& num, const Data& den, Data& result);
		
	}
}
