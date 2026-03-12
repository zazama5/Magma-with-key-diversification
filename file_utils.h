#include <cstdint>
#include <string>
#include <vector>
std::vector<uint8_t> readFile(const std::string &filename);//Читаем байты из файла
void writeFile(const std::string &filename, const std::vector<uint8_t> &data);//Записываем байты в файл
std::vector<uint64_t> splitBlocksForEncrypt (const std::vector<uint8_t>& data);//Собираем байты в блоки по 8 байт и добавляем паддинг
std::vector<uint64_t> splitBlocksForDecrypt (const std::vector<uint8_t>& data);//Просто собираем блоки в байты
std::vector<uint8_t> joinBlocksForDecrypt(const std::vector<uint64_t> &blocks);//Разбиваем блоки на байты и собираем текст воедино убирая паддинг
std::vector<uint8_t> joinBlocksForEncrypt(const std::vector<uint64_t> &blocks);//Просто разбиваем блоки на байты