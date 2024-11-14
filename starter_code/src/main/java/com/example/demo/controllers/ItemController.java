package com.example.demo.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.repositories.ItemRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/api/item")
public class ItemController {

        private final Logger log = LoggerFactory.getLogger(getClass());

	@Autowired
	private ItemRepository itemRepository;
	
	@GetMapping
	public ResponseEntity<List<Item>> getItems() {
		return ResponseEntity.ok(itemRepository.findAll());
	}
	
	@GetMapping("/{id}")
	public ResponseEntity<Item> getItemById(@PathVariable Long id) {
		return ResponseEntity.of(itemRepository.findById(id));
	}
	
    @GetMapping("/name/{name}")
    public ResponseEntity<List<Item>> getItemsByName(@PathVariable String name) {
        
        List<Item> items = itemRepository.findByName(name);

        if (items == null || items.isEmpty()) {
            log.error("item not found for item: {}",name); 
            return ResponseEntity.notFound().build();
        }
       return ResponseEntity.ok(items);

    }
	
}
