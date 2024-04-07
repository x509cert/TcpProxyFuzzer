#include <string>
#include <array>

static std::array<std::string,6> logo { 
R"(                                                          
 _____         _____                 _____                     
|_   _|___ ___|  _  |___ ___ _ _ _ _|   __|_ _ ___ ___ ___ ___ 
  | | |  _| . |   __|  _| . |_'_| | |   __| | |- _|- _| -_|  _|
  |_| |___|  _|__|  |_| |___|_,_|_  |__|  |___|___|___|___|_|  
          |_|                   |___|                                                                 
)"
};

void PrintLogo() {
	for(auto& line : logo)
		printf("%s", line.c_str());
}
