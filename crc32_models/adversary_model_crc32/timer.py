
import time
class TimeTracker:
    def __init__(self):
        self.start_time_in_ns = 0
        self.end_time_in_ns = 0
        self.time_elapsed = 0

    def record_start_timestamp(self):
        self.start_time_in_ns = time.time_ns()
        self.end_time_in_ns = 0

    def record_end_timestamp(self):
        if self.start_time_in_ns == 0:
            print(f"The clock is not started to record end time stamp.")
            return
        else:
            self.end_time_in_ns = time.time_ns()
            self.calculate_time_elapsed()

    def calculate_time_elapsed(self):
        self.time_elapsed = self.end_time_in_ns - self.start_time_in_ns
#
#
# if __name__ == '__main__':
#     tt = TimeTracker()
#     tt.record_start_timestamp()
#     time.sleep(2)
#     tt.record_end_timestamp()
#
#     print(f'Time elapsed : {tt.time_elapsed}')
