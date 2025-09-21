// PawnIO - Input-output driver
// Copyright (C) 2023  namazso <admin@namazso.eu>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// Linking PawnIO statically or dynamically with other modules is making a
// combined work based on PawnIO. Thus, the terms and conditions of the GNU
// General Public License cover the whole combination.
//
// In addition, as a special exception, the copyright holders of PawnIO give
// you permission to combine PawnIO program with free software programs or
// libraries that are released under the GNU LGPL and with independent modules
// that communicate with PawnIO solely through the device IO control
// interface. You may copy and distribute such a system following the terms of
// the GNU GPL for PawnIO and the licenses of the other code concerned,
// provided that you include the source code of that other code when and as
// the GNU GPL requires distribution of source code.
//
// Note that this exception does not include programs that communicate with
// PawnIO over the Pawn interface. This means that all modules loaded into
// PawnIO must be compatible with this licence, including the earlier
// exception clause. We recommend using the GNU Lesser General Public License
// version 2.1 to fulfill this requirement.
//
// For alternative licensing options, please contact the copyright holder at
// admin@namazso.eu.
//
// Note that people who make modified versions of PawnIO are not obligated to
// grant this special exception for their modified versions; it is their
// choice whether to do so. The GNU General Public License gives permission
// to release a modified version without this exception; this exception also
// makes it possible to release a modified version which carries forward this
// exception.

#pragma once

#include "kallocator.h"

template <typename T>
struct klist_node {
  LIST_ENTRY entry;
  T value;
};

template <typename T>
FORCEINLINE klist_node<T>* get_node_from_entry(PLIST_ENTRY entry) {
  return CONTAINING_RECORD(entry, klist_node<T>, entry);
}

template <typename List>
class klist_iterator {
public:
  using iterator_category = std::bidirectional_iterator_tag;
  using value_type = List::value_type;
  using difference_type = List::difference_type;
  using pointer = List::pointer;
  using reference = List::reference;

  friend List;

  template <typename OtherList>
  friend class klist_iterator;
private:
  List* _list;
  PLIST_ENTRY _entry;

  FORCEINLINE klist_iterator()
      : _list(nullptr), _entry(nullptr) {}

  FORCEINLINE klist_iterator(List* list, PLIST_ENTRY entry)
      : _list(list), _entry(entry) {}

public:
  FORCEINLINE operator klist_iterator<const List>() const {
    return klist_iterator<const List>(_list, _entry);
  }

  FORCEINLINE [[nodiscard]] PLIST_ENTRY as_entry() const { return _entry; }

  FORCEINLINE reference operator*() const {
    if (_entry == _list->end().as_entry())
      __fastfail(FAST_FAIL_RANGE_CHECK_FAILURE);
    
    return get_node_from_entry<value_type>(_entry)->value;
  }

  FORCEINLINE pointer operator->() const {
    if (_entry == _list->end().as_entry())
      __fastfail(FAST_FAIL_RANGE_CHECK_FAILURE);

    return &get_node_from_entry<value_type>(_entry)->value;
  }

  FORCEINLINE klist_iterator& operator++() {
    _entry = _entry->Flink;
    return *this;
  }

  FORCEINLINE klist_iterator operator++(int) {
    klist_iterator tmp = *this;
    _entry = _entry->Flink;
    return tmp;
  }

  FORCEINLINE klist_iterator& operator--() {
    _entry = _entry->Blink;
    return *this;
  }

  FORCEINLINE klist_iterator operator--(int) {
    klist_iterator tmp = *this;
    _entry = _entry->Blink;
    return tmp;
  }

  FORCEINLINE [[nodiscard]] bool operator==(const klist_iterator& other) const {
    return _entry == other._entry;
  }

  FORCEINLINE [[nodiscard]] bool operator!=(const klist_iterator& other) const {
    return _entry != other._entry;
  }
};

template <class T, class Allocator = kallocator<klist_node<T>>>
class klist {
public:
  using value_type = T;
  using allocator_type = Allocator;
  using size_type = size_t;
  using difference_type = ptrdiff_t;
  using reference = value_type&;
  using const_reference = const value_type&;
  using pointer = std::allocator_traits<Allocator>::pointer;
  using const_pointer = std::allocator_traits<Allocator>::const_pointer;
  using iterator = klist_iterator<klist<T, Allocator>>;
  using const_iterator = klist_iterator<const klist<T, Allocator>>;
  using reverse_iterator = std::reverse_iterator<iterator>;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

private:
  LIST_ENTRY _head{
    &_head,
    &_head
  };
  Allocator _alloc{};

public:
  FORCEINLINE constexpr klist() noexcept = default;

  FORCEINLINE klist(const klist& other) = delete;

  FORCEINLINE klist(klist&& other) noexcept
      : _alloc(std::move(other._alloc)) {
    InitializeListHead(&_head);
    if (!other.empty()) {
      _head = other._head;
      _head.Flink->Blink = &_head;
      _head.Blink->Flink = &_head;
      InitializeListHead(&other._head);
    }
  }

  FORCEINLINE klist& operator=(const klist& other) = delete;

  FORCEINLINE klist& operator=(klist&& other) noexcept {
    if (this != &other) {
      clear();
      if constexpr (std::allocator_traits<Allocator>::propagate_on_container_move_assignment::value) {
        _alloc = std::move(other._alloc);
      }
      if (!other.empty()) {
        _head = other._head;
        _head.Flink->Blink = &_head;
        _head.Blink->Flink = &_head;
        InitializeListHead(&other._head);
      }
    }
    return *this;
  }

  FORCEINLINE ~klist() {
    clear();
  }

  FORCEINLINE [[nodiscard]] iterator iter_from_entry(PLIST_ENTRY entry) { return iterator(this, entry); }
  FORCEINLINE [[nodiscard]] const_iterator iter_from_entry(PLIST_ENTRY entry) const { return const_iterator(this, entry); }
  FORCEINLINE [[nodiscard]] const_iterator citer_from_entry(PLIST_ENTRY entry) const { return const_iterator(this, entry); }
  
  FORCEINLINE [[nodiscard]] iterator begin() { return iterator(this, _head.Flink); }
  FORCEINLINE [[nodiscard]] const_iterator begin() const { return const_iterator(this, _head.Flink); }
  FORCEINLINE [[nodiscard]] const_iterator cbegin() const { return const_iterator(this, _head.Flink); }
  
  FORCEINLINE [[nodiscard]] iterator end() { return iterator(this, &_head); }
  FORCEINLINE [[nodiscard]] const_iterator end() const { return const_iterator(this, &_head); }
  FORCEINLINE [[nodiscard]] const_iterator cend() const { return const_iterator(this, &_head); }
  
  FORCEINLINE [[nodiscard]] iterator rbegin() { return reverse_iterator(end()); }
  FORCEINLINE [[nodiscard]] const_iterator rbegin() const { return const_reverse_iterator(end()); }
  FORCEINLINE [[nodiscard]] const_iterator crbegin() const { return const_reverse_iterator(cend()); }
  
  FORCEINLINE [[nodiscard]] iterator rend() { return reverse_iterator(begin()); }
  FORCEINLINE [[nodiscard]] const_iterator rend() const { return const_reverse_iterator(begin()); }
  FORCEINLINE [[nodiscard]] const_iterator crend() const { return const_reverse_iterator(cbegin()); }

  FORCEINLINE [[nodiscard]] bool empty() const { return IsListEmpty(&_head) != FALSE; }

  FORCEINLINE void clear();
  FORCEINLINE iterator insert(const_iterator pos, const T& value);
  FORCEINLINE iterator insert(const_iterator pos, T&& value);
  //FORCEINLINE iterator insert(const_iterator pos, size_type count, const T& value);
  //FORCEINLINE template <class InputIt>
  //FORCEINLINE iterator insert(const_iterator pos, InputIt first, InputIt last);
  //FORCEINLINE iterator insert(const_iterator pos, std::initializer_list<T> ilist);
  template <class... Args>
  FORCEINLINE iterator emplace(const_iterator pos, Args&&... args);
  FORCEINLINE iterator erase(iterator pos);
  FORCEINLINE iterator erase(const_iterator pos);
  FORCEINLINE iterator erase(iterator first, iterator last);
  FORCEINLINE iterator erase(const_iterator first, const_iterator last);
  FORCEINLINE iterator push_back(const T& value);
  FORCEINLINE iterator push_back(T&& value);
  //template <class... Args>
  //FORCEINLINE reference emplace_back(Args&&... args);
  FORCEINLINE iterator push_front(const T& value);
  FORCEINLINE iterator push_front(T&& value);
  template <class... Args>
  FORCEINLINE iterator emplace_front(Args&&... args);
  //template <class... Args>
  //FORCEINLINE reference emplace_front(Args&&... args);
  //FORCEINLINE void resize(size_type count);
  //FORCEINLINE void resize(size_type count, const value_type& value);
  FORCEINLINE void swap(klist& other) noexcept;
};

template <class T, class Allocator>
void klist<T, Allocator>::clear() {
  while (!empty()) {
    erase(begin());
  }
}

template <class T, class Allocator>
 klist<T, Allocator>::iterator klist<T, Allocator>::insert(const_iterator pos, const T& value) {
  auto* node = std::allocator_traits<Allocator>::allocate(_alloc, 1);
  if (!node)
    return end();
  std::allocator_traits<Allocator>::construct(_alloc, &node->value, value);

  InsertHeadList(pos._entry->Blink, &node->entry);
  return iterator(this, &node->entry);
}

template <class T, class Allocator>
 klist<T, Allocator>::iterator klist<T, Allocator>::insert(const_iterator pos, T&& value) {
  auto* node = std::allocator_traits<Allocator>::allocate(_alloc, 1);
  if (!node)
    return end();
  std::allocator_traits<Allocator>::construct(_alloc, &node->value, std::move(value));

  InsertHeadList(pos._entry->Blink, &node->entry);
  return iterator(this, &node->entry);
}

template <class T, class Allocator>
template <class... Args>
 klist<T, Allocator>::iterator klist<T, Allocator>::emplace(const_iterator pos, Args&&... args) {
  auto* node = std::allocator_traits<Allocator>::allocate(_alloc, 1);
  if (!node)
    return end();
  std::allocator_traits<Allocator>::construct(_alloc, &node->value, std::forward<Args>(args)...);

  InsertHeadList(pos._entry->Blink, &node->entry);
  return iterator(this, &node->entry);
}

template <class T, class Allocator>
 klist<T, Allocator>::iterator klist<T, Allocator>::erase(iterator pos) {
  PLIST_ENTRY next = pos._entry->Flink;
  RemoveEntryList(pos._entry);

  auto* node = get_node_from_entry<T>(pos._entry);
  std::allocator_traits<Allocator>::destroy(_alloc, &node->value);
  std::allocator_traits<Allocator>::deallocate(_alloc, node, 1);

  return iterator(this, next);
}

template <class T, class Allocator>
 klist<T, Allocator>::iterator klist<T, Allocator>::erase(const_iterator pos) {
  return erase(iterator(this, pos._entry));
}

template <class T, class Allocator>
 klist<T, Allocator>::iterator klist<T, Allocator>::erase(iterator first, iterator last) {
  while (first != last) {
    first = erase(first);
  }
  return last;
}

template <class T, class Allocator>
 klist<T, Allocator>::iterator klist<T, Allocator>::erase(const_iterator first, const_iterator last) {
  return erase(iterator(this, first._entry), iterator(this, last._entry));
}

template <class T, class Allocator>
 klist<T, Allocator>::iterator klist<T, Allocator>::push_back(const T& value) {
  return insert(end(), value);
}

template <class T, class Allocator>
 klist<T, Allocator>::iterator klist<T, Allocator>::push_back(T&& value) {
  return insert(end(), std::move(value));
}

template <class T, class Allocator>
 klist<T, Allocator>::iterator klist<T, Allocator>::push_front(const T& value) {
  return insert(begin(), value);
}

template <class T, class Allocator>
 klist<T, Allocator>::iterator klist<T, Allocator>::push_front(T&& value) {
  return insert(begin(), std::move(value));
}

template <class T, class Allocator>
template <class... Args>
 klist<T, Allocator>::iterator klist<T, Allocator>::emplace_front(Args&&... args) {
  return emplace(begin(), std::forward<Args>(args)...);
}

template <class T, class Allocator>
void klist<T, Allocator>::swap(klist& other) noexcept {
  if (this == &other)
    return;

  if constexpr (std::allocator_traits<Allocator>::propagate_on_container_swap::value) {
    std::swap(_alloc, other._alloc);
  }

  // Swap only if both lists are non-empty
  if (!empty() && !other.empty()) {
    std::swap(_head, other._head);

    // Fix the pointers
    _head.Flink->Blink = &_head;
    _head.Blink->Flink = &_head;
    other._head.Flink->Blink = &other._head;
    other._head.Blink->Flink = &other._head;
  }
  // If this is empty but other is not
  else if (empty() && !other.empty()) {
    _head = other._head;
    _head.Flink->Blink = &_head;
    _head.Blink->Flink = &_head;
    InitializeListHead(&other._head);
  }
  // If this is not empty but other is
  else if (!empty() && other.empty()) {
    other._head = _head;
    other._head.Flink->Blink = &other._head;
    other._head.Blink->Flink = &other._head;
    InitializeListHead(&_head);
  }
  // If both are empty, nothing to do
}
