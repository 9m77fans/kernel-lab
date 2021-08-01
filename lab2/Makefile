all:
	$(CC) -Wall -o list list.c -lpthread -g -fsanitize=thread
	$(CC) -Wall -o rcu_list rcu_list.c -lpthread -g -fsanitize=thread


clean:
	rm -f list rcu_list
