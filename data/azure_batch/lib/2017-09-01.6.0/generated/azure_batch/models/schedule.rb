# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # The schedule according to which jobs will be created
    #
    #
    class Schedule

      include MsRestAzure

      # @return [DateTime] The earliest time at which any job may be created
      # under this job schedule. If you do not specify a doNotRunUntil time,
      # the schedule becomes ready to create jobs immediately.
      attr_accessor :do_not_run_until

      # @return [DateTime] A time after which no job will be created under this
      # job schedule. The schedule will move to the completed state as soon as
      # this deadline is past and there is no active job under this job
      # schedule. If you do not specify a doNotRunAfter time, and you are
      # creating a recurring job schedule, the job schedule will remain active
      # until you explicitly terminate it.
      attr_accessor :do_not_run_after

      # @return [Duration] The time interval, starting from the time at which
      # the schedule indicates a job should be created, within which a job must
      # be created. If a job is not created within the startWindow interval,
      # then the 'opportunity' is lost; no job will be created until the next
      # recurrence of the schedule. If the schedule is recurring, and the
      # startWindow is longer than the recurrence interval, then this is
      # equivalent to an infinite startWindow, because the job that is 'due' in
      # one recurrenceInterval is not carried forward into the next recurrence
      # interval. The default is infinite. The minimum value is 1 minute. If
      # you specify a lower value, the Batch service rejects the schedule with
      # an error; if you are calling the REST API directly, the HTTP status
      # code is 400 (Bad Request).
      attr_accessor :start_window

      # @return [Duration] The time interval between the start times of two
      # successive jobs under the job schedule. A job schedule can have at most
      # one active job under it at any given time. Because a job schedule can
      # have at most one active job under it at any given time, if it is time
      # to create a new job under a job schedule, but the previous job is still
      # running, the Batch service will not create the new job until the
      # previous job finishes. If the previous job does not finish within the
      # startWindow period of the new recurrenceInterval, then no new job will
      # be scheduled for that interval. For recurring jobs, you should normally
      # specify a jobManagerTask in the jobSpecification. If you do not use
      # jobManagerTask, you will need an external process to monitor when jobs
      # are created, add tasks to the jobs and terminate the jobs ready for the
      # next recurrence. The default is that the schedule does not recur: one
      # job is created, within the startWindow after the doNotRunUntil time,
      # and the schedule is complete as soon as that job finishes. The minimum
      # value is 1 minute. If you specify a lower value, the Batch service
      # rejects the schedule with an error; if you are calling the REST API
      # directly, the HTTP status code is 400 (Bad Request).
      attr_accessor :recurrence_interval


      #
      # Mapper for Schedule class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'Schedule',
          type: {
            name: 'Composite',
            class_name: 'Schedule',
            model_properties: {
              do_not_run_until: {
                client_side_validation: true,
                required: false,
                serialized_name: 'doNotRunUntil',
                type: {
                  name: 'DateTime'
                }
              },
              do_not_run_after: {
                client_side_validation: true,
                required: false,
                serialized_name: 'doNotRunAfter',
                type: {
                  name: 'DateTime'
                }
              },
              start_window: {
                client_side_validation: true,
                required: false,
                serialized_name: 'startWindow',
                type: {
                  name: 'TimeSpan'
                }
              },
              recurrence_interval: {
                client_side_validation: true,
                required: false,
                serialized_name: 'recurrenceInterval',
                type: {
                  name: 'TimeSpan'
                }
              }
            }
          }
        }
      end
    end
  end
end
